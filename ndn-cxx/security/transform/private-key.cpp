/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2020 Regents of the University of California.
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

#include "ndn-cxx/security/transform/private-key.hpp"
#include "ndn-cxx/security/transform/base64-decode.hpp"
#include "ndn-cxx/security/transform/base64-encode.hpp"
#include "ndn-cxx/security/transform/buffer-source.hpp"
#include "ndn-cxx/security/transform/digest-filter.hpp"
#include "ndn-cxx/security/transform/stream-sink.hpp"
#include "ndn-cxx/security/transform/stream-source.hpp"
#include "ndn-cxx/security/impl/openssl-helper.hpp"
#include "ndn-cxx/security/key-params.hpp"
#include "ndn-cxx/encoding/buffer-stream.hpp"
#include "ndn-cxx/util/random.hpp"

#include <boost/lexical_cast.hpp>
#include <boost/scope_exit.hpp>
// #include <mcl/bn256.hpp> // TODO: remove
// #include <bls/bls384_256.h>
// #include <bls/bls.hpp>
#include <bls/bls256.h>
#include <bls/bls.hpp>
#include <mcl/bn.hpp>
#include <cstring>
#include <iostream>

#define ENSURE_PRIVATE_KEY_LOADED(key) \
  do { \
    if ((key) == nullptr) \
      NDN_THROW(Error("Private key has not been loaded yet")); \
  } while (false)

#define ENSURE_PRIVATE_KEY_NOT_LOADED(key) \
  do { \
    if ((key) != nullptr) \
      NDN_THROW(Error("Private key has already been loaded")); \
  } while (false)

namespace ndn {
namespace security {
namespace transform {

bool initBNPairing() {
  // TODO: blslib

  static bool once = [](){
        bls::init();
        std::cout << "BLS inited!" << std::endl;
        return true;
    }();
  
  return once;


  // static bool once = [](){
  //       mcl::bn256::initPairing();
  //       std::cout << "Pairing inited!" << std::endl;
  //       return true;
  //   }();
  
  // return once;
}

static void
opensslInitAlgorithms()
{
#if OPENSSL_VERSION_NUMBER < 0x1010000fL
  static bool isInitialized = false;
  if (!isInitialized) {
    OpenSSL_add_all_algorithms();
    isInitialized = true;
  }
#endif // OPENSSL_VERSION_NUMBER < 0x1010000fL
}

class PrivateKey::Impl : noncopyable
{
public:
  ~Impl()
  {
    EVP_PKEY_free(key);
  }

public:
  EVP_PKEY* key = nullptr;
  // shared_ptr<mcl::bn256::Fr> bls_skey = nullptr;
  // shared_ptr<mcl::bn256::G2> bls_pkey = nullptr;
  // TODO: blslib
  shared_ptr<bls::SecretKey> bls_skey = nullptr;

#if OPENSSL_VERSION_NUMBER < 0x1010100fL
  size_t keySize = 0; // in bits, used only for HMAC
#endif
};

PrivateKey::PrivateKey()
  : m_impl(make_unique<Impl>())
{
}

PrivateKey::~PrivateKey() = default;

KeyType
PrivateKey::getKeyType() const
{
  if (!m_impl->key && !m_impl->bls_skey)
    return KeyType::NONE;
  
  if (m_impl->bls_skey)
    return KeyType::BLS;

  switch (detail::getEvpPkeyType(m_impl->key)) {
  case EVP_PKEY_RSA:
    return KeyType::RSA;
  case EVP_PKEY_EC:
    return KeyType::EC;
  case EVP_PKEY_HMAC:
    return KeyType::HMAC;
  default:
    return KeyType::NONE;
  }
}

size_t
PrivateKey::getKeySize() const // TODO: BLS support
{
  switch (getKeyType()) {
    case KeyType::RSA:
    case KeyType::EC:
      return static_cast<size_t>(EVP_PKEY_bits(m_impl->key));
    case KeyType::HMAC: {
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
      size_t nBytes = 0;
      EVP_PKEY_get_raw_private_key(m_impl->key, nullptr, &nBytes);
      return nBytes * 8;
#else
      return m_impl->keySize;
#endif
    }
    default:
      return 0;
  }
}

ConstBufferPtr
PrivateKey::getKeyDigest(DigestAlgorithm algo) const
{
  if (getKeyType() != KeyType::HMAC)
    NDN_THROW(Error("Digest is not supported for key type " +
                    boost::lexical_cast<std::string>(getKeyType())));

  const uint8_t* buf = nullptr;
  size_t len = 0;
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
  buf = EVP_PKEY_get0_hmac(m_impl->key, &len);
#else
  const auto* octstr = reinterpret_cast<ASN1_OCTET_STRING*>(EVP_PKEY_get0(m_impl->key));
  buf = octstr->data;
  len = octstr->length;
#endif
  if (buf == nullptr)
    NDN_THROW(Error("Failed to obtain raw key pointer"));
  if (len * 8 != getKeySize())
    NDN_THROW(Error("Key length mismatch"));

  OBufferStream os;
  bufferSource(buf, len) >> digestFilter(algo) >> streamSink(os);
  return os.buf();
}

void
PrivateKey::loadRaw(KeyType type, const uint8_t* buf, size_t size)
{
  ENSURE_PRIVATE_KEY_NOT_LOADED(m_impl->key);

  int pkeyType;
  switch (type) {
  case KeyType::HMAC:
    pkeyType = EVP_PKEY_HMAC;
    break;
  default:
    NDN_THROW(std::invalid_argument("Unsupported key type " + boost::lexical_cast<std::string>(type)));
  }

  m_impl->key =
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
      EVP_PKEY_new_raw_private_key(pkeyType, nullptr, buf, size);
#else
      EVP_PKEY_new_mac_key(pkeyType, nullptr, buf, static_cast<int>(size));
#endif
  if (m_impl->key == nullptr)
    NDN_THROW(Error("Failed to load private key"));

#if OPENSSL_VERSION_NUMBER < 0x1010100fL
  m_impl->keySize = size * 8;
#endif
}

void
PrivateKey::loadPkcs1(const uint8_t* buf, size_t size)
{
  ENSURE_PRIVATE_KEY_NOT_LOADED(m_impl->key);
  opensslInitAlgorithms();

  if (d2i_AutoPrivateKey(&m_impl->key, &buf, static_cast<long>(size)) == nullptr)
    NDN_THROW(Error("Failed to load private key"));
}

void
PrivateKey::loadPkcs1(std::istream& is)
{
  OBufferStream os;
  streamSource(is) >> streamSink(os);
  this->loadPkcs1(os.buf()->data(), os.buf()->size());
}


// TODO: workaround for bls key
void
PrivateKey::loadPlain(const uint8_t* buf, size_t size)
{
  initBNPairing();

  // TODO: blslib

  m_impl->bls_skey = make_shared<bls::SecretKey>();
  std::printf("trying to deserialize bls secrect key\n"); // TODO: remove
  try{
    std::string sec_str((char*)buf, size);
    std::cout << "sec key size " << size << std::endl;
    std::cout << "sec key hex str:\n" << std::endl;
    m_impl->bls_skey->deserializeHexStr(sec_str);
  }
  catch (const std::runtime_error&) {
    std::printf("failed to deserialize bls secrect key\n"); // TODO: remove
    NDN_THROW(Error("Failed to load bls private key"));
  }
  std::printf("successfully loaded bls secrect key\n"); // TODO: remove





  // m_impl->bls_skey = make_shared<mcl::bn256::Fr>();
  // std::printf("trying to deserialize bls secrect key\n"); // TODO: remove
  // try{
  //   m_impl->bls_skey->deserialize(buf, size);
  // }
  // catch (const std::runtime_error&) {
  //   std::printf("failed to deserialize bls secrect key\n"); // TODO: remove
  //   NDN_THROW(Error("Failed to load bls private key"));
  // }
  // std::printf("successfully loaded bls secrect key\n"); // TODO: remove
}

// TODO: workaround for bls key
void
PrivateKey::loadPlain(std::istream& is)
{
  OBufferStream os;
  streamSource(is) >> streamSink(os);
  this->loadPlain(os.buf()->data(), os.buf()->size());
}





void
PrivateKey::loadPkcs1Base64(const uint8_t* buf, size_t size)
{
  OBufferStream os;
  bufferSource(buf, size) >> base64Decode() >> streamSink(os);
  this->loadPkcs1(os.buf()->data(), os.buf()->size());
}

void
PrivateKey::loadPkcs1Base64(std::istream& is)
{
  OBufferStream os;
  streamSource(is) >> base64Decode() >> streamSink(os);
  this->loadPkcs1(os.buf()->data(), os.buf()->size());
}




// work around for BLS key, TODO: error check
void
PrivateKey::loadPlainBase64(const uint8_t* buf, size_t size)
{
  OBufferStream os;
  std::cout << "loadPlainBase64 size " << size << std::endl;
  bufferSource(buf, size) >> base64Decode() >> streamSink(os);
  this->loadPlain(os.buf()->data(), os.buf()->size());
}


// work around for BLS key, TODO: error check
void
PrivateKey::loadPlainBase64(std::istream& is)
{
  OBufferStream os;
  // streamSource(is) >> base64Decode() >> streamSink(os); // TODO: remove 64
  streamSource(is)  >> streamSink(os);
  std::printf("buf size %d\n\n",  os.buf()->size());
  this->loadPlain(os.buf()->data(), os.buf()->size());
}













void
PrivateKey::loadPkcs8(const uint8_t* buf, size_t size, const char* pw, size_t pwLen)
{
  BOOST_ASSERT(std::strlen(pw) == pwLen);
  ENSURE_PRIVATE_KEY_NOT_LOADED(m_impl->key);
  opensslInitAlgorithms();

  detail::Bio membio(BIO_s_mem());
  if (!membio.write(buf, size))
    NDN_THROW(Error("Failed to copy buffer"));

  if (d2i_PKCS8PrivateKey_bio(membio, &m_impl->key, nullptr, const_cast<char*>(pw)) == nullptr)
    NDN_THROW(Error("Failed to load private key"));
}

static inline int
passwordCallbackWrapper(char* buf, int size, int rwflag, void* u)
{
  BOOST_ASSERT(size >= 0);
  auto cb = reinterpret_cast<PrivateKey::PasswordCallback*>(u);
  return (*cb)(buf, static_cast<size_t>(size), rwflag);
}

void
PrivateKey::loadPkcs8(const uint8_t* buf, size_t size, PasswordCallback pwCallback)
{
  ENSURE_PRIVATE_KEY_NOT_LOADED(m_impl->key);
  opensslInitAlgorithms();

  detail::Bio membio(BIO_s_mem());
  if (!membio.write(buf, size))
    NDN_THROW(Error("Failed to copy buffer"));

  if (pwCallback)
    m_impl->key = d2i_PKCS8PrivateKey_bio(membio, nullptr, &passwordCallbackWrapper, &pwCallback);
  else
    m_impl->key = d2i_PKCS8PrivateKey_bio(membio, nullptr, nullptr, nullptr);

  if (m_impl->key == nullptr)
    NDN_THROW(Error("Failed to load private key"));
}

void
PrivateKey::loadPkcs8(std::istream& is, const char* pw, size_t pwLen)
{
  OBufferStream os;
  streamSource(is) >> streamSink(os);
  this->loadPkcs8(os.buf()->data(), os.buf()->size(), pw, pwLen);
}

void
PrivateKey::loadPkcs8(std::istream& is, PasswordCallback pwCallback)
{
  OBufferStream os;
  streamSource(is) >> streamSink(os);
  this->loadPkcs8(os.buf()->data(), os.buf()->size(), pwCallback);
}

void
PrivateKey::loadPkcs8Base64(const uint8_t* buf, size_t size, const char* pw, size_t pwLen)
{
  OBufferStream os;
  bufferSource(buf, size) >> base64Decode() >> streamSink(os);
  this->loadPkcs8(os.buf()->data(), os.buf()->size(), pw, pwLen);
}

void
PrivateKey::loadPkcs8Base64(const uint8_t* buf, size_t size, PasswordCallback pwCallback)
{
  OBufferStream os;
  bufferSource(buf, size) >> base64Decode() >> streamSink(os);
  this->loadPkcs8(os.buf()->data(), os.buf()->size(), pwCallback);
}

void
PrivateKey::loadPkcs8Base64(std::istream& is, const char* pw, size_t pwLen)
{
  OBufferStream os;
  streamSource(is) >> base64Decode() >> streamSink(os);
  this->loadPkcs8(os.buf()->data(), os.buf()->size(), pw, pwLen);
}

void
PrivateKey::loadPkcs8Base64(std::istream& is, PasswordCallback pwCallback)
{
  OBufferStream os;
  streamSource(is) >> base64Decode() >> streamSink(os);
  this->loadPkcs8(os.buf()->data(), os.buf()->size(), pwCallback);
}

// TODO: store plain text for bls key type
void
PrivateKey::savePlainBase64(std::ostream& os) const
{
  // bufferSource(*this->toPlain()) >> base64Encode() >> streamSink(os); // TODO: remove 64
  bufferSource(*this->toPlain()) >> streamSink(os);
  std::printf("\nprivate-key.cpp line 317 saved to streamSink\n");
}

void
PrivateKey::savePkcs1(std::ostream& os) const
{
  bufferSource(*this->toPkcs1()) >> streamSink(os);
}

void
PrivateKey::savePkcs1Base64(std::ostream& os) const
{
  bufferSource(*this->toPkcs1()) >> base64Encode() >> streamSink(os);
}

void
PrivateKey::savePkcs8(std::ostream& os, const char* pw, size_t pwLen) const
{
  bufferSource(*this->toPkcs8(pw, pwLen)) >> streamSink(os);
}

void
PrivateKey::savePkcs8(std::ostream& os, PasswordCallback pwCallback) const
{
  bufferSource(*this->toPkcs8(pwCallback)) >> streamSink(os);
}

void
PrivateKey::savePkcs8Base64(std::ostream& os, const char* pw, size_t pwLen) const
{
  bufferSource(*this->toPkcs8(pw, pwLen)) >> base64Encode() >> streamSink(os);
}

void
PrivateKey::savePkcs8Base64(std::ostream& os, PasswordCallback pwCallback) const
{
  bufferSource(*this->toPkcs8(pwCallback)) >> base64Encode() >> streamSink(os);
}

ConstBufferPtr
PrivateKey::derivePublicKey() const
{
  if(getKeyType() == KeyType::BLS) {

    // TODO: bls lib   failed
    std::printf("1111 BLS public key\n");
    ENSURE_PRIVATE_KEY_LOADED(m_impl->bls_skey);
    initBNPairing();
    std::printf("222 BLS public key\n");

    bls::PublicKey pub;

    // TODO:
    std::string sec_str = m_impl->bls_skey->serializeToHexStr();
    std::cout << "derive pub key: sec hex key:\n" << sec_str << std::endl;    


    m_impl->bls_skey->getPublicKey(pub);
    std::printf("333 BLS public key\n"); 
    std::string pub_str = pub.serializeToHexStr();
    std::printf("444 BLS public key\n"); 
    auto result = make_shared<Buffer>(pub_str.c_str(), pub_str.size());
    std::printf("derived BLS public key\n"); 
    return result;







    // ENSURE_PRIVATE_KEY_LOADED(m_impl->bls_skey);

    // const size_t buf_size = 2048;
    // uint8_t buf[buf_size];
    // size_t keysize = m_impl->bls_pkey->serialize(buf, buf_size);
    // auto result = make_shared<Buffer>(buf, keysize);
    // std::printf("derived BLS public key\n"); 
    // return result;



  }
  ENSURE_PRIVATE_KEY_LOADED(m_impl->key);

  uint8_t* pkcs8 = nullptr;
  int len = i2d_PUBKEY(m_impl->key, &pkcs8);
  if (len < 0)
    NDN_THROW(Error("Failed to derive public key"));

  auto result = make_shared<Buffer>(pkcs8, len);
  OPENSSL_free(pkcs8);

  return result;
}

ConstBufferPtr
PrivateKey::decrypt(const uint8_t* cipherText, size_t cipherLen) const
{
  ENSURE_PRIVATE_KEY_LOADED(m_impl->key);

  int keyType = detail::getEvpPkeyType(m_impl->key);
  switch (keyType) {
    case EVP_PKEY_NONE:
      NDN_THROW(Error("Failed to determine key type"));
    case EVP_PKEY_RSA:
      return rsaDecrypt(cipherText, cipherLen);
    default:
      NDN_THROW(Error("Decryption is not supported for key type " + to_string(keyType)));
  }
}

// TODO: workaround for bls key
ConstBufferPtr
PrivateKey::doBlsSign(const uint8_t* buf, size_t size) const
{ 


  // // TODO: blslib
  std::printf("\nSigning data with BLS key\n"); // TODO:
  initBNPairing();
  bls::Signature sig;
  m_impl->bls_skey->sign(sig, buf, size);
  std::string sig_str = sig.serializeToHexStr();
  auto buffer = make_shared<Buffer>(sig_str.c_str(), sig_str.size());
  std::printf("\nSigned data with BLS key\n"); // TODO:
  return buffer; 











  // std::printf("\nSigning data with BLS key\n"); // TODO:
  // using namespace mcl::bn256;
  // initBNPairing();
  // // std::printf("\nmcl::bn256::initBNPairing()  finished\n");
  // G1 sign, Hm;
  // Fp t;
  // t.setHashOf(buf, size);
  // mapToG1(Hm, t);
  // G1::mul(sign, Hm, *(m_impl->bls_skey));
  // const size_t buf_size = 4096;
  // uint8_t bls_buf[buf_size];
  // size_t sig_size = sign.serialize(bls_buf, buf_size);
  // auto buffer = make_shared<Buffer>(bls_buf, sig_size);
  // std::printf("\nSigned data with BLS key\n"); // TODO
  // return buffer;
}

void*
PrivateKey::getEvpPkey() const
{
  return m_impl->key;
}

// TODO: not tested
ConstBufferPtr
PrivateKey::toPlain() const
{
  if (!m_impl->bls_skey)
    NDN_THROW(Error("Cannot convert BLS key to plain text, BLS key not found"));


  // TODO: blslib
  std::printf("\nconverting bls secrect key to hex\n");
  std::string sec_str = m_impl->bls_skey->serializeToHexStr();
  std::cout << "toPlain: sec hex key:\n" << sec_str << std::endl;
  const uint8_t* buf = reinterpret_cast<const uint8_t*>(sec_str.data());

  auto buffer = make_shared<Buffer>(buf, sec_str.size());  
  std::printf("\nconverted bls secrect key to hex\n"); // TODO: to delete


  return buffer;





  

  // std::printf("\nconverting bls secrect key to plain\n");   // TODO: to delete
  // const size_t buf_size = 2048;
  // uint8_t buf[buf_size];
  // size_t keysize = m_impl->bls_skey->serialize(buf, buf_size);
  // auto buffer = make_shared<Buffer>(buf, keysize);
  // std::printf("\nconverted bls secrect key to plain\n"); // TODO: to delete
  // return buffer;

  // std::printf("\nconverting bls secrect key to plain\n");   // TODO: to delete
  // std::ostringstream os;
  // os << *(m_impl->bls_skey);
  // auto str = os.str();
  // const char* cstr = str.c_str();
  // auto buffer = make_shared<Buffer>(cstr, str.length());
  // std::printf("\nconverted bls secrect key to plain\n"); // TODO: to delete
  // return buffer;
}

ConstBufferPtr
PrivateKey::toPkcs1() const
{
  ENSURE_PRIVATE_KEY_LOADED(m_impl->key);
  opensslInitAlgorithms();

  detail::Bio membio(BIO_s_mem());
  if (!i2d_PrivateKey_bio(membio, m_impl->key))
    NDN_THROW(Error("Cannot convert key to PKCS #1 format"));

  auto buffer = make_shared<Buffer>(BIO_pending(membio));
  if (!membio.read(buffer->data(), buffer->size()))
    NDN_THROW(Error("Read error during PKCS #1 conversion"));

  return buffer;
}

ConstBufferPtr
PrivateKey::toPkcs8(const char* pw, size_t pwLen) const
{
  BOOST_ASSERT(std::strlen(pw) == pwLen);
  ENSURE_PRIVATE_KEY_LOADED(m_impl->key);
  opensslInitAlgorithms();

  detail::Bio membio(BIO_s_mem());
  if (!i2d_PKCS8PrivateKey_bio(membio, m_impl->key, EVP_aes_256_cbc(), nullptr, 0,
                               nullptr, const_cast<char*>(pw)))
    NDN_THROW(Error("Cannot convert key to PKCS #8 format"));

  auto buffer = make_shared<Buffer>(BIO_pending(membio));
  if (!membio.read(buffer->data(), buffer->size()))
    NDN_THROW(Error("Read error during PKCS #8 conversion"));

  return buffer;
}

ConstBufferPtr
PrivateKey::toPkcs8(PasswordCallback pwCallback) const
{
  ENSURE_PRIVATE_KEY_LOADED(m_impl->key);
  opensslInitAlgorithms();

  detail::Bio membio(BIO_s_mem());
  if (!i2d_PKCS8PrivateKey_bio(membio, m_impl->key, EVP_aes_256_cbc(), nullptr, 0,
                               &passwordCallbackWrapper, &pwCallback))
    NDN_THROW(Error("Cannot convert key to PKCS #8 format"));

  auto buffer = make_shared<Buffer>(BIO_pending(membio));
  if (!membio.read(buffer->data(), buffer->size()))
    NDN_THROW(Error("Read error during PKCS #8 conversion"));

  return buffer;
}

ConstBufferPtr
PrivateKey::rsaDecrypt(const uint8_t* cipherText, size_t cipherLen) const
{
  detail::EvpPkeyCtx ctx(m_impl->key);

  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    NDN_THROW(Error("Failed to initialize decryption context"));

  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    NDN_THROW(Error("Failed to set padding"));

  size_t outlen = 0;
  // Determine buffer length
  if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, cipherText, cipherLen) <= 0)
    NDN_THROW(Error("Failed to estimate output length"));

  auto out = make_shared<Buffer>(outlen);
  if (EVP_PKEY_decrypt(ctx, out->data(), &outlen, cipherText, cipherLen) <= 0)
    NDN_THROW(Error("Failed to decrypt ciphertext"));

  out->resize(outlen);
  return out;
}

unique_ptr<PrivateKey>
PrivateKey::generateRsaKey(uint32_t keySize)
{
  detail::EvpPkeyCtx kctx(EVP_PKEY_RSA);

  if (EVP_PKEY_keygen_init(kctx) <= 0)
    NDN_THROW(PrivateKey::Error("Failed to initialize RSA keygen context"));

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, static_cast<int>(keySize)) <= 0)
    NDN_THROW(PrivateKey::Error("Failed to set RSA key length"));

  auto privateKey = make_unique<PrivateKey>();
  if (EVP_PKEY_keygen(kctx, &privateKey->m_impl->key) <= 0)
    NDN_THROW(PrivateKey::Error("Failed to generate RSA key"));

  return privateKey;
}

unique_ptr<PrivateKey>
PrivateKey::generateEcKey(uint32_t keySize)
{
  EC_KEY* eckey = nullptr;
  switch (keySize) {
  case 224:
    eckey = EC_KEY_new_by_curve_name(NID_secp224r1);
    break;
  case 256:
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // same as secp256r1
    break;
  case 384:
    eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
    break;
  case 521:
    eckey = EC_KEY_new_by_curve_name(NID_secp521r1);
    break;
  default:
    NDN_THROW(std::invalid_argument("Unsupported EC key length " + to_string(keySize)));
  }
  if (eckey == nullptr)
    NDN_THROW(Error("Failed to set EC curve"));

  BOOST_SCOPE_EXIT(&eckey) {
    EC_KEY_free(eckey);
  } BOOST_SCOPE_EXIT_END

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
  EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
#endif // OPENSSL_VERSION_NUMBER < 0x1010000fL

  if (EC_KEY_generate_key(eckey) != 1) {
    NDN_THROW(Error("Failed to generate EC key"));
  }

  auto privateKey = make_unique<PrivateKey>();
  privateKey->m_impl->key = EVP_PKEY_new();
  if (privateKey->m_impl->key == nullptr)
    NDN_THROW(Error("Failed to create EVP_PKEY"));
  if (EVP_PKEY_set1_EC_KEY(privateKey->m_impl->key, eckey) != 1)
    NDN_THROW(Error("Failed to assign EC key"));

  return privateKey;
}

unique_ptr<PrivateKey>
PrivateKey::generateBlsKey(uint32_t keySize)
{ 
  // TODO: blslib
  
  auto privateKey = make_unique<PrivateKey>();
  initBNPairing();
  printf("generateBlsKey\n\n");
  privateKey->m_impl->bls_skey = make_shared<bls::SecretKey>();
  privateKey->m_impl->bls_skey->init();
  printf("generated BlsKey\n\n");

  //  // TODO: test serialize
  // std::printf("\ntry derive when generate\n");
  // bls::PublicKey pub;
  // privateKey->m_impl->bls_skey->getPublicKey(pub);
  // std::printf("\ntry derive when generate\n");



  return privateKey;
  








// // TODO: the following is a test of bls key generation
//   auto privateKey = make_unique<PrivateKey>();
//   initBNPairing();
//   privateKey->m_impl->bls_skey = make_shared<mcl::bn256::Fr>();
//   privateKey->m_impl->bls_pkey = make_shared<mcl::bn256::G2>();
//   mcl::bn256::G2 Q;
//   mcl::bn256::mapToG2(Q, 1);
//   privateKey->m_impl->bls_skey->setRand();
//   mcl::bn256::G2::mul(*(privateKey->m_impl->bls_pkey), Q, *(privateKey->m_impl->bls_skey));
//   std::printf("\n\ngenerated bls_skey and bls_pkey\n\n");
//   return privateKey;
}

unique_ptr<PrivateKey>
PrivateKey::generateHmacKey(uint32_t keySize)
{
  std::vector<uint8_t> rawKey(keySize / 8);
  random::generateSecureBytes(rawKey.data(), rawKey.size());

  auto privateKey = make_unique<PrivateKey>();
  try {
    privateKey->loadRaw(KeyType::HMAC, rawKey.data(), rawKey.size());
  }
  catch (const PrivateKey::Error&) {
    NDN_THROW(PrivateKey::Error("Failed to generate HMAC key"));
  }

  return privateKey;
}

unique_ptr<PrivateKey>
generatePrivateKey(const KeyParams& keyParams)
{
  switch (keyParams.getKeyType()) {
    case KeyType::RSA: {
      const RsaKeyParams& rsaParams = static_cast<const RsaKeyParams&>(keyParams);
      return PrivateKey::generateRsaKey(rsaParams.getKeySize());
    }
    case KeyType::EC: {
      const EcKeyParams& ecParams = static_cast<const EcKeyParams&>(keyParams);
      return PrivateKey::generateEcKey(ecParams.getKeySize());
    }
    case KeyType::BLS: {
      const BlsKeyParams& blsParams = static_cast<const BlsKeyParams&>(keyParams);
      return PrivateKey::generateBlsKey(blsParams.getKeySize());
    }
    case KeyType::HMAC: {
      const HmacKeyParams& hmacParams = static_cast<const HmacKeyParams&>(keyParams);
      return PrivateKey::generateHmacKey(hmacParams.getKeySize());
    }
    default:
      NDN_THROW(std::invalid_argument("Unsupported key type " +
                                      boost::lexical_cast<std::string>(keyParams.getKeyType())));
  }
}

} // namespace transform
} // namespace security
} // namespace ndn
