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

#include "ndn-cxx/security/transform/public-key.hpp"
#include "ndn-cxx/security/transform/base64-decode.hpp"
#include "ndn-cxx/security/transform/base64-encode.hpp"
#include "ndn-cxx/security/transform/buffer-source.hpp"
#include "ndn-cxx/security/transform/stream-sink.hpp"
#include "ndn-cxx/security/transform/stream-source.hpp"
#include "ndn-cxx/security/impl/openssl-helper.hpp"
#include "ndn-cxx/encoding/buffer-stream.hpp"

#include <mcl/bn256.hpp>

#define ENSURE_PUBLIC_KEY_LOADED(key) \
  do { \
    if ((key) == nullptr) \
      NDN_THROW(Error("Public key has not been loaded yet")); \
  } while (false)

#define ENSURE_PUBLIC_KEY_NOT_LOADED(key) \
  do { \
    if ((key) != nullptr) \
      NDN_THROW(Error("Public key has already been loaded")); \
  } while (false)

namespace ndn {
namespace security {
namespace transform {

class PublicKey::Impl
{
public:
  Impl() noexcept
    : key(nullptr), bls_pkey(nullptr)
  {
  }

  ~Impl()
  {
    EVP_PKEY_free(key);
  }

public:
  EVP_PKEY* key;
  shared_ptr<mcl::bn256::G2> bls_pkey;
};

PublicKey::PublicKey()
  : m_impl(make_unique<Impl>())
{
}

PublicKey::~PublicKey() = default;

KeyType
PublicKey::getKeyType() const
{
  if (!m_impl->key && !m_impl->bls_pkey)
    return KeyType::NONE;
  
  if(m_impl->bls_pkey)
    return KeyType::BLS;

  switch (detail::getEvpPkeyType(m_impl->key)) {
  case EVP_PKEY_RSA:
    return KeyType::RSA;
  case EVP_PKEY_EC:
    return KeyType::EC;
  default:
    return KeyType::NONE;
  }
}

void
PublicKey::loadBls(const uint8_t* buf, size_t size)
{
  ENSURE_PUBLIC_KEY_NOT_LOADED(m_impl->bls_pkey);
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wvexing-parse"
      bool initBNPairing();
  #pragma GCC diagnostic pop

  initBNPairing(); // TODO: delete
  if(size == 0)
    NDN_THROW(Error("Failed to load BLS public key"));
  m_impl->bls_pkey = make_shared<mcl::bn256::G2>();
  std::printf("trying to deserialize bls public key\n");
  m_impl->bls_pkey->deserialize(buf, size);


  // std::string str((char*)buf, size); // TODO: explict type cast here, need further change
  // std::istringstream is(str);
  
  // // TODO: remove
  

  // is >> *(m_impl->bls_pkey);
  std::printf("\nloaded bls public key, transform/public-key.cpp\n");
}

void
PublicKey::loadPkcs8(const uint8_t* buf, size_t size)
{
  ENSURE_PUBLIC_KEY_NOT_LOADED(m_impl->key);

  if (d2i_PUBKEY(&m_impl->key, &buf, static_cast<long>(size)) == nullptr)
    NDN_THROW(Error("Failed to load public key"));
}

void
PublicKey::loadPkcs8(std::istream& is)
{
  OBufferStream os;
  streamSource(is) >> streamSink(os);
  this->loadPkcs8(os.buf()->data(), os.buf()->size());
}

void
PublicKey::loadPkcs8Base64(const uint8_t* buf, size_t size)
{
  OBufferStream os;
  bufferSource(buf, size) >> base64Decode() >> streamSink(os);
  this->loadPkcs8(os.buf()->data(), os.buf()->size());
}

void
PublicKey::loadPkcs8Base64(std::istream& is)
{
  OBufferStream os;
  streamSource(is) >> base64Decode() >> streamSink(os);
  this->loadPkcs8(os.buf()->data(), os.buf()->size());
}

void
PublicKey::savePkcs8(std::ostream& os) const
{
  bufferSource(*this->toPkcs8()) >> streamSink(os);
}

void
PublicKey::savePkcs8Base64(std::ostream& os) const
{
  bufferSource(*this->toPkcs8()) >> base64Encode() >> streamSink(os);
}

ConstBufferPtr
PublicKey::encrypt(const uint8_t* plainText, size_t plainLen) const
{
  ENSURE_PUBLIC_KEY_LOADED(m_impl->key);

  int keyType = detail::getEvpPkeyType(m_impl->key);
  switch (keyType) {
    case EVP_PKEY_NONE:
      NDN_THROW(Error("Failed to determine key type"));
    case EVP_PKEY_RSA:
      return rsaEncrypt(plainText, plainLen);
    default:
      NDN_THROW(Error("Encryption is not supported for key type " + to_string(keyType)));
  }
}

void*
PublicKey::getEvpPkey() const
{
  return m_impl->key;
}

ConstBufferPtr
PublicKey::toPkcs8() const
{
  ENSURE_PUBLIC_KEY_LOADED(m_impl->key);

  uint8_t* pkcs8 = nullptr;
  int len = i2d_PUBKEY(m_impl->key, &pkcs8);
  if (len < 0)
    NDN_THROW(Error("Cannot convert key to PKCS #8 format"));

  auto buffer = make_shared<Buffer>(pkcs8, len);
  OPENSSL_free(pkcs8);

  return buffer;
}

ConstBufferPtr
PublicKey::rsaEncrypt(const uint8_t* plainText, size_t plainLen) const
{
  detail::EvpPkeyCtx ctx(m_impl->key);

  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    NDN_THROW(Error("Failed to initialize encryption context"));

  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    NDN_THROW(Error("Failed to set padding"));

  size_t outlen = 0;
  // Determine buffer length
  if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plainText, plainLen) <= 0)
    NDN_THROW(Error("Failed to estimate output length"));

  auto out = make_shared<Buffer>(outlen);
  if (EVP_PKEY_encrypt(ctx, out->data(), &outlen, plainText, plainLen) <= 0)
    NDN_THROW(Error("Failed to encrypt plaintext"));

  out->resize(outlen);
  return out;
}

bool
PublicKey::doBlsVerification(const uint8_t* blob, size_t blobLen, const uint8_t* sig, size_t sigLen) const
{
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wvexing-parse"
      bool initBNPairing();
  #pragma GCC diagnostic pop

  using namespace mcl::bn256;
  G2 Q;
  
	mapToG2(Q, 1);
  Fp12 e1, e2;
  G1 blob_sig, given_sig;
  Fp t;
  given_sig.deserialize(sig, sigLen);
  t.setHashOf(blob, blobLen);
  mapToG1(blob_sig, t);
  pairing(e1, given_sig, Q);
  pairing(e2, blob_sig, *m_impl->bls_pkey);
  

  return e1 == e2;
}

} // namespace transform
} // namespace security
} // namespace ndn
