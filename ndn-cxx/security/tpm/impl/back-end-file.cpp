/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2019 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#include "ndn-cxx/security/tpm/impl/back-end-file.hpp"
#include "ndn-cxx/security/tpm/impl/key-handle-mem.hpp"
#include "ndn-cxx/security/transform.hpp"
#include "ndn-cxx/security/transform/private-key.hpp"
#include "ndn-cxx/encoding/buffer-stream.hpp"

#include <cstdlib>
#include <fstream>
#include <sys/stat.h>

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>

namespace ndn {
namespace security {
namespace tpm {

namespace fs = boost::filesystem;
using transform::PrivateKey;

class BackEndFile::Impl
{
public:
  explicit
  Impl(const std::string& dir)
  {
    if (!dir.empty()) {
      m_keystorePath = fs::path(dir);
    }
#ifdef NDN_CXX_HAVE_TESTS
    else if (std::getenv("TEST_HOME") != nullptr) {
      m_keystorePath = fs::path(std::getenv("TEST_HOME")) / ".ndn";
    }
#endif // NDN_CXX_HAVE_TESTS
    else if (std::getenv("HOME") != nullptr) {
      m_keystorePath = fs::path(std::getenv("HOME")) / ".ndn";
    }
    else {
      m_keystorePath = fs::current_path() / ".ndn";
    }

    m_keystorePath /= "ndnsec-key-file";
    fs::create_directories(m_keystorePath);
  }

  fs::path
  toFileName(const Name& keyName) const
  {
    std::ostringstream os;
    {
      using namespace transform;
      bufferSource(keyName.wireEncode().wire(), keyName.wireEncode().size())
        >> digestFilter(DigestAlgorithm::SHA256)
        >> hexEncode()
        >> streamSink(os);
    }
    return m_keystorePath / (os.str() + ".privkey");
  }

private:
  fs::path m_keystorePath;
};

BackEndFile::BackEndFile(const std::string& location)
  : m_impl(make_unique<Impl>(location))
{
}

BackEndFile::~BackEndFile() = default;

const std::string&
BackEndFile::getScheme()
{
  static std::string scheme = "tpm-file";
  return scheme;
}

bool
BackEndFile::doHasKey(const Name& keyName) const
{
  if (!fs::exists(m_impl->toFileName(keyName)))
    return false;

  try {
    loadKey(keyName);
    return true;
  }
  catch (const std::runtime_error&) {
    return false;
  }
}

unique_ptr<KeyHandle>
BackEndFile::doGetKeyHandle(const Name& keyName) const
{
  if (!doHasKey(keyName))
    return nullptr;

  return make_unique<KeyHandleMem>(loadKey(keyName));
}

unique_ptr<KeyHandle> // TODO: add BLS support
BackEndFile::doCreateKey(const Name& identityName, const KeyParams& params)
{
  switch (params.getKeyType()) {
  case KeyType::RSA:
  case KeyType::EC:
  case KeyType::BLS:
    break;
  default:
    NDN_THROW(std::invalid_argument("File-based TPM does not support creating a key of type " +
                                    boost::lexical_cast<std::string>(params.getKeyType())));
  }

  shared_ptr<PrivateKey> key(transform::generatePrivateKey(params).release());
  unique_ptr<KeyHandle> keyHandle = make_unique<KeyHandleMem>(key);

  Name keyName = constructAsymmetricKeyName(*keyHandle, identityName, params);
  keyHandle->setKeyName(keyName);

  try {
    saveKey(keyName, *key);
    return keyHandle;
  }
  catch (const std::runtime_error&) {
    NDN_THROW_NESTED(Error("Cannot write key to file"));
  }
}

void
BackEndFile::doDeleteKey(const Name& keyName)
{
  auto keyPath = m_impl->toFileName(keyName);
  if (!fs::exists(keyPath))
    return;

  try {
    fs::remove(keyPath);
  }
  catch (const fs::filesystem_error&) {
    NDN_THROW_NESTED(Error("Cannot remove key file"));
  }
}

ConstBufferPtr
BackEndFile::doExportKey(const Name& keyName, const char* pw, size_t pwLen)
{
  unique_ptr<PrivateKey> key;
  try {
    key = loadKey(keyName);
  }
  catch (const PrivateKey::Error&) {
    NDN_THROW_NESTED(Error("Cannot export private key"));
  }

  OBufferStream os;
  key->savePkcs8(os, pw, pwLen);
  return os.buf();
}

void
BackEndFile::doImportKey(const Name& keyName, const uint8_t* buf, size_t size, const char* pw, size_t pwLen)
{
  try {
    PrivateKey key;
    key.loadPkcs8(buf, size, pw, pwLen);
    saveKey(keyName, key);
  }
  catch (const PrivateKey::Error&) {
    NDN_THROW_NESTED(Error("Cannot import private key"));
  }
}

void
BackEndFile::doImportKey(const Name& keyName, shared_ptr<transform::PrivateKey> key)
{
  try {
    saveKey(keyName, *key);
  }
  catch (const PrivateKey::Error&) {
    NDN_THROW_NESTED(Error("Cannot import private key"));
  }
}

unique_ptr<PrivateKey>

BackEndFile::loadKey(const Name& keyName) const
{
  std::ifstream is(m_impl->toFileName(keyName).string());
  auto key = make_unique<PrivateKey>();
  // TODO: support BLS !!!!!!!!!!!!!!!!!!!
  try {
    key->loadPkcs1Base64(is);
  }
  catch (const PrivateKey::Error&) {
    try {
      // try load BLS key
      key->loadPlainBase64(is);
    }
    catch (const PrivateKey::Error&) {
      std::printf("\nfailed to load bls key\n"); // TODO: remove
      NDN_THROW(Error("failed to load bls key"));
    }
  } 
  
  
  return key;
}

void
BackEndFile::saveKey(const Name& keyName, const PrivateKey& key)
{
  std::string fileName = m_impl->toFileName(keyName).string();
  // TODO:
  std::printf("fileName %s\n", fileName.c_str());
  std::ofstream os(fileName);
  // special case for BLS key type, need further refactoring
  if (key.getKeyType() == KeyType::BLS) {
    // TODO: save plain base64
    std::printf("\n\ngot BLS key to save\n\n"); // TODO: delete printf
    key.savePlainBase64(os);
    std::printf("\n\nsaved BLS key\n\n"); // TODO: delete printf
  }
  else{
    key.savePkcs1Base64(os);
  }
  
  // set file permission
  ::chmod(fileName.data(), 0000400);
}

} // namespace tpm
} // namespace security
} // namespace ndn
