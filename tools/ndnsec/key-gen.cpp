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

#include "ndnsec.hpp"
#include "util.hpp"

#include "ndn-cxx/util/io.hpp"
#include <bls/bls384_256.h>
#include <bls/bls.hpp>


// #include <mcl/bn_c384_256.h>
// #include <mcl/bn256.hpp>

#define ASSERT(x) { if (!(x)) { printf("err %s:%d\n", __FILE__, __LINE__); } }

namespace ndn {
namespace ndnsec {

int
ndnsec_key_gen(int argc, char** argv)
{
  namespace po = boost::program_options;

  Name identityName;
  bool wantNotDefault = false;
  char keyTypeChoice;
  char keyIdTypeChoice;
  std::string userKeyId;

// TODO: test bls
  bls::init();
  bls::SecretKey sec;
  bls::PublicKey pub;

  // keygen
  
  sec.init();

  sec.getPublicKey(pub);
  std::string pubstr = pub.serializeToHexStr();
  std::string secstr = sec.serializeToHexStr();
  std::cout << "pub\n" << pubstr << std::endl;
  std::cout<< "sec\n" << secstr << std::endl;


  // sign
  

  
  
/*
  {
    using namespace mcl::bn256;

    // setup parameter
    std::string m = "hello mcl";
    initPairing();
    G2 Q;
	  mapToG2(Q, 1);

    // generate secret key and public key
    Fr s;
    G2 pub;
    // KeyGen(s, pub, Q);
    s.setRand();
	  G2::mul(pub, Q, s); // pub = sQ

    std::ofstream os("xxxxtmp");
    os << s;
    std::cout << "\n\n stored to file" << std::endl;

    std::cout << "secret key " << s << std::endl;
    std::cout << "public key " << pub << std::endl;

    std::string sec_str;
    s.getStr(sec_str);
    std::string pub_str;
    pub.getStr(pub_str);

    std::ostringstream os_sec;
    os_sec << s;
    std::ostringstream os_pub;
    os_pub << pub;

    std::cout << "secret key str \n" << os_sec.str() << std::endl;
    std::cout << "public key str \n" << os_pub.str() << std::endl;
    Fr s_loaded;
    std::istringstream iss(os_sec.str());
    iss >> s_loaded;
    G2 pub_loaded;
    std::istringstream isp(os_pub.str());
    isp >> pub_loaded;
    
    std::cout << "loaded sec key \n" << std::endl;



    // // TODO: test
    // G2 pub_loaded_test;
    // // std::istringstream isp_test("3 4755531472481367320050321855359261053908859428675729523208717474045434288222 1214869512283725956150263339259846474892970500454552944251614220306976737118");
    // std::istringstream isp_test("2 6546227188043548762710371008467396985457043891793766953586101882713137472036 15910615552758269835124486855865246826342720849428341402232124162937770466994");
    // isp_test >> pub_loaded;




   

    // sign
    G1 sign;
    // Sign(sign, s, m);
    G1 Hm;
    // Hash(Hm, m);
    Fp t;
    // t.setHashOf(const void * msg, size_t msgSize);
    t.setHashOf(m);
    mapToG1(Hm, t);
    G1::mul(sign, Hm, s); // sign = s H(m)
    std::cout << "msg " << m << std::endl;
    std::cout << "sign " << sign << std::endl;

    // verify
    // bool ok = Verify(sign, Q, pub, m);
    Fp12 e1, e2;
    G1 Hm2;
    // Hash(Hm2, m);
    Fp t2;
    t2.setHashOf(m);
    mapToG1(Hm2, t2);
    pairing(e1, sign, Q); // e1 = e(sign, Q)
    pairing(e2, Hm2, pub_loaded); // e2 = e(Hm, sQ)
	  bool ok = (e1 == e2);
    std::cout << "verify " << (ok ? "ok" : "ng") << std::endl;

  }
*/

  po::options_description description(
    "Usage: ndnsec key-gen [-h] [-n] [-t TYPE] [-k KEYIDTYPE|--keyid KEYID] [-i] IDENTITY\n"
    "\n"
    "Options");
  description.add_options()
    ("help,h", "produce help message")
    ("identity,i",    po::value<Name>(&identityName), "identity name, e.g., /ndn/edu/ucla/alice")
    ("not-default,n", po::bool_switch(&wantNotDefault), "do not set the identity as default")
    ("type,t",        po::value<char>(&keyTypeChoice)->default_value('e'),
                      "key type: 'r' for RSA, 'e' for ECDSA, 'b' for BLS")
    ("keyid-type,k",  po::value<char>(&keyIdTypeChoice),
                      "key id type: 'h' for the SHA-256 of the public key, 'r' for a 64-bit "
                      "random number (the default unless --keyid is specified)")
    ("keyid",         po::value<std::string>(&userKeyId), "user-specified key id")
    ;

  po::positional_options_description p;
  p.add("identity", 1);

  po::variables_map vm;
  try {
    po::store(po::command_line_parser(argc, argv).options(description).positional(p).run(), vm);
    po::notify(vm);
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << "\n\n"
              << description << std::endl;
    return 2;
  }

  if (vm.count("help") > 0) {
    std::cout << description << std::endl;
    return 0;
  }

  if (vm.count("identity") == 0) {
    std::cerr << "ERROR: you must specify an identity" << std::endl;
    return 2;
  }

  KeyIdType keyIdType = KeyIdType::RANDOM;
  Name::Component userKeyIdComponent;

  if (vm.count("keyid") > 0) {
    if (vm.count("keyid-type") > 0) {
      std::cerr << "ERROR: cannot specify both '--keyid' and '--keyid-type'" << std::endl;
      return 2;
    }

    keyIdType = KeyIdType::USER_SPECIFIED;
    userKeyIdComponent = name::Component::fromEscapedString(userKeyId);
    if (userKeyIdComponent.empty()) {
      std::cerr << "ERROR: key id cannot be an empty name component" << std::endl;
      return 2;
    }
    if (!userKeyIdComponent.isGeneric()) {
      std::cerr << "ERROR: key id must be a GenericNameComponent" << std::endl;
      return 2;
    }
  }

  if (vm.count("keyid-type") > 0) {
    switch (keyIdTypeChoice) {
    case 'h':
      keyIdType = KeyIdType::SHA256;
      break;
    case 'r':
      // KeyIdType::RANDOM is the default
      break;
    default:
      std::cerr << "ERROR: unrecognized key id type '" << keyIdTypeChoice << "'" << std::endl;
      return 2;
    }
  }

  unique_ptr<KeyParams> params;
  switch (keyTypeChoice) {
  case 'r':
    if (keyIdType == KeyIdType::USER_SPECIFIED) {
      params = make_unique<RsaKeyParams>(userKeyIdComponent);
    }
    else {
      params = make_unique<RsaKeyParams>(detail::RsaKeyParamsInfo::getDefaultSize(), keyIdType);
    }
    break;
  case 'e':
    if (keyIdType == KeyIdType::USER_SPECIFIED) {
      params = make_unique<EcKeyParams>(userKeyIdComponent);
    }
    else {
      params = make_unique<EcKeyParams>(detail::EcKeyParamsInfo::getDefaultSize(), keyIdType);
    }
    break;
  case 'b':
    if (keyIdType == KeyIdType::USER_SPECIFIED) {
      params = make_unique<BlsKeyParams>(userKeyIdComponent);
    }
    else {
      params = make_unique<BlsKeyParams>(detail::BlsKeyParamsInfo::getDefaultSize(), keyIdType);
    }
    break;
  default:
    std::cerr << "ERROR: unrecognized key type '" << keyTypeChoice << "'" << std::endl;
    return 2;
  }

  security::v2::KeyChain keyChain;

  security::Identity identity;
  security::Key key;
  try {
    identity = keyChain.getPib().getIdentity(identityName);
    key = keyChain.createKey(identity, *params);    // TODO: partially implemented, faked with EC key
  }
  catch (const security::Pib::Error&) {
    // identity doesn't exist, so create it and generate key
    identity = keyChain.createIdentity(identityName, *params);
    key = identity.getDefaultKey();
  }

  if (!wantNotDefault) {
    keyChain.setDefaultKey(identity, key);
    keyChain.setDefaultIdentity(identity);
  }

  // TODO:
  std::cerr << "Successfully created key" << std::endl;
  io::save(key.getDefaultCertificate(), std::cout);

  return 0;
}

} // namespace ndnsec
} // namespace ndn
