/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2014 Regents of the University of California.
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

#include "name.hpp"

#include "boost-test.hpp"
#include <boost/tuple/tuple.hpp>
#include <boost/mpl/vector.hpp>

namespace ndn {

BOOST_AUTO_TEST_SUITE(TestName)

static const uint8_t TestName[] = {
        0x7,  0x14, // Name
          0x8,  0x5, // NameComponent
              0x6c,  0x6f,  0x63,  0x61,  0x6c,
          0x8,  0x3, // NameComponent
              0x6e,  0x64,  0x6e,
          0x8,  0x6, // NameComponent
              0x70,  0x72,  0x65,  0x66,  0x69,  0x78
};

const uint8_t Name1[] = {0x7,  0x7, // Name
                           0x8,  0x5, // NameComponent
                             0x6c,  0x6f,  0x63,  0x61,  0x6c};

const uint8_t Name2[] = {0x7,  0xc, // Name
                           0x8,  0x5, // NameComponent
                             0x6c,  0x6f,  0x63,  0x61,  0x6c,
                           0x8,  0x3, // NameComponent
                             0x6e,  0x64,  0x6e};


BOOST_AUTO_TEST_CASE(Basic)
{
  Name name("/hello/world");

  BOOST_CHECK_NO_THROW(name.at(0));
  BOOST_CHECK_NO_THROW(name.at(1));
  BOOST_CHECK_NO_THROW(name.at(-1));
  BOOST_CHECK_NO_THROW(name.at(-2));

  BOOST_CHECK_THROW(name.at(2), Name::Error);
  BOOST_CHECK_THROW(name.at(-3), Name::Error);
}

BOOST_AUTO_TEST_CASE(Encode)
{
  Name name("/local/ndn/prefix");

  const Block &wire = name.wireEncode();

  // for (Buffer::const_iterator i = wire.begin();
  //      i != wire.end();
  //      ++i)
  //   {
  //     std::ios::fmtflags saveFlags = std::cout.flags(std::ios::hex);

  //     if (i != wire.begin())
  //       std::cout << ", ";
  //     std::cout << "0x" << static_cast<uint32_t>(*i);

  //     std::cout.flags(saveFlags);
  //   }
  // std::cout << std::endl;

  BOOST_CHECK_EQUAL_COLLECTIONS(TestName, TestName+sizeof(TestName),
                                wire.begin(), wire.end());
}


BOOST_AUTO_TEST_CASE(Decode)
{
  Block block(TestName, sizeof(TestName));

  Name name(block);

  BOOST_CHECK_EQUAL(name.toUri(), "/local/ndn/prefix");
}

BOOST_AUTO_TEST_CASE(AppendsAndMultiEncode)
{
  Name name("/local");

  BOOST_CHECK_EQUAL_COLLECTIONS(name.wireEncode().begin(), name.wireEncode().end(),
                                Name1, Name1 + sizeof(Name1));

  name.append("ndn");

  BOOST_CHECK_EQUAL_COLLECTIONS(name.wireEncode().begin(), name.wireEncode().end(),
                                Name2, Name2 + sizeof(Name2));

  name.append("prefix");
  BOOST_CHECK_EQUAL_COLLECTIONS(name.wireEncode().begin(), name.wireEncode().end(),
                                TestName, TestName+sizeof(TestName));
}

BOOST_AUTO_TEST_CASE(AppendNumber)
{
  Name name;
  for (uint32_t i = 0; i < 10; i++)
    {
      name.appendNumber(i);
    }

  BOOST_CHECK_EQUAL(name.size(), 10);

  for (uint32_t i = 0; i < 10; i++)
    {
      BOOST_CHECK_EQUAL(name[i].toNumber(), i);
    }
}

class Numeric
{
public:
  typedef std::list<boost::tuple<function<name::Component(uint64_t)>,
                                 function<uint64_t(const name::Component&)>,
                                 function<Name&(Name&, uint64_t)>,
                                 Name/*expected*/,
                                 uint64_t/*value*/,
                                 function<bool(const name::Component&)> > > Dataset;

  Numeric()
  {
    dataset.push_back(boost::make_tuple(bind(&name::Component::fromNumberWithMarker,
                                             0xAA, _1),
                                        bind(&name::Component::toNumberWithMarker, _1, 0xAA),
                                        bind(&Name::appendNumberWithMarker, _1, 0xAA, _2),
                                        Name("/%AA%03%E8"),
                                        1000,
                                        bind(&name::Component::isNumberWithMarker, _1, 0xAA)));
    dataset.push_back(boost::make_tuple(&name::Component::fromSegment,
                                        bind(&name::Component::toSegment, _1),
                                        bind(&Name::appendSegment, _1, _2),
                                        Name("/%00%27%10"),
                                        10000,
                                        bind(&name::Component::isSegment, _1)));
    dataset.push_back(boost::make_tuple(&name::Component::fromSegmentOffset,
                                        bind(&name::Component::toSegmentOffset, _1),
                                        bind(&Name::appendSegmentOffset, _1, _2),
                                        Name("/%FB%00%01%86%A0"),
                                        100000,
                                        bind(&name::Component::isSegmentOffset, _1)));
    dataset.push_back(boost::make_tuple(&name::Component::fromVersion,
                                        bind(&name::Component::toVersion, _1),
                                        bind(static_cast<Name&(Name::*)(uint64_t)>(
                                               &Name::appendVersion), _1, _2),
                                        Name("/%FD%00%0FB%40"),
                                        1000000,
                                        bind(&name::Component::isVersion, _1)));
    dataset.push_back(boost::make_tuple(&name::Component::fromSequenceNumber,
                                        bind(&name::Component::toSequenceNumber, _1),
                                        bind(&Name::appendSequenceNumber, _1, _2),
                                        Name("/%FE%00%98%96%80"),
                                        10000000,
                                        bind(&name::Component::isSequenceNumber, _1)));
  }

  Dataset dataset;
};

class Timestamp
{
public:
  typedef std::list<boost::tuple<function<name::Component(const time::system_clock::TimePoint&)>,
                                 function<time::system_clock::TimePoint(const name::Component&)>,
                                 function<Name&(Name&, const time::system_clock::TimePoint&)>,
                                 Name/*expected*/,
                                 time::system_clock::TimePoint/*value*/,
                                 function<bool(const name::Component&)> > > Dataset;
  Timestamp()
  {
    dataset.push_back(boost::make_tuple(&name::Component::fromTimestamp,
                                        bind(&name::Component::toTimestamp, _1),
                                        bind(&Name::appendTimestamp, _1, _2),
                                        Name("/%FC%00%04%7BE%E3%1B%00%00"),
                                        time::getUnixEpoch() + time::days(14600/*40 years*/),
                                        bind(&name::Component::isTimestamp, _1)));
  }

  Dataset dataset;
};

typedef boost::mpl::vector<Numeric, Timestamp> ConventionsDatasets;

BOOST_FIXTURE_TEST_CASE_TEMPLATE(NamingConventions, T, ConventionsDatasets, T)
{
  // // These octets are obtained by the snippet below.
  // // This check is intended to detect unexpected encoding change in the future.
  // for (typename T::Dataset::const_iterator it = this->dataset.begin();
  //      it != this->dataset.end(); ++it) {
  //   Name name;
  //   name.append(it->template get<0>()(it->template get<4>()));
  //   std::cout << name << std::endl;
  // }

  name::Component invalidComponent1;
  name::Component invalidComponent2("1234567890");

  for (typename T::Dataset::const_iterator it = this->dataset.begin();
       it != this->dataset.end(); ++it) {
    const Name& expected = it->template get<3>();
    BOOST_TEST_MESSAGE("Check " << expected[0].toUri());

    name::Component actualComponent = it->template get<0>()(it->template get<4>());
    BOOST_CHECK_EQUAL(actualComponent, expected[0]);

    Name actualName;
    it->template get<2>()(actualName, it->template get<4>());
    BOOST_CHECK_EQUAL(actualName, expected);

    BOOST_CHECK_EQUAL(it->template get<5>()(expected[0]), true);
    BOOST_REQUIRE_NO_THROW(it->template get<1>()(expected[0]));
    BOOST_CHECK_EQUAL(it->template get<1>()(expected[0]), it->template get<4>());

    BOOST_CHECK_EQUAL(it->template get<5>()(invalidComponent1), false);
    BOOST_CHECK_EQUAL(it->template get<5>()(invalidComponent2), false);

    BOOST_REQUIRE_THROW(it->template get<1>()(invalidComponent1), name::Component::Error);
    BOOST_REQUIRE_THROW(it->template get<1>()(invalidComponent2), name::Component::Error);
  }
}

BOOST_AUTO_TEST_CASE(GetSuccessor)
{
  BOOST_CHECK_EQUAL(Name("ndn:/%00%01/%01%02").getSuccessor(), Name("ndn:/%00%01/%01%03"));
  BOOST_CHECK_EQUAL(Name("ndn:/%00%01/%01%FF").getSuccessor(), Name("ndn:/%00%01/%02%00"));
  BOOST_CHECK_EQUAL(Name("ndn:/%00%01/%FF%FF").getSuccessor(), Name("ndn:/%00%01/%00%00%00"));
  BOOST_CHECK_EQUAL(Name().getSuccessor(), Name("ndn:/%00"));
}

BOOST_AUTO_TEST_CASE(Markers)
{
  Name name;
  uint64_t number;

  BOOST_REQUIRE_NO_THROW(number = name.appendSegment(30923).at(-1).toSegment());
  BOOST_CHECK_EQUAL(number, 30923);

  BOOST_REQUIRE_NO_THROW(number = name.appendSegmentOffset(589).at(-1).toSegmentOffset());
  BOOST_CHECK_EQUAL(number, 589);

  BOOST_REQUIRE_NO_THROW(number = name.appendVersion().at(-1).toVersion());

  BOOST_REQUIRE_NO_THROW(number = name.appendVersion(25912).at(-1).toVersion());
  BOOST_CHECK_EQUAL(number, 25912);

  const time::system_clock::TimePoint tp = time::system_clock::now();
  time::system_clock::TimePoint tp2;
  BOOST_REQUIRE_NO_THROW(tp2 = name.appendTimestamp(tp).at(-1).toTimestamp());
  BOOST_CHECK_LE(std::abs(time::duration_cast<time::microseconds>(tp2 - tp).count()), 1);

  BOOST_REQUIRE_NO_THROW(number = name.appendSequenceNumber(11676).at(-1).toSequenceNumber());
  BOOST_CHECK_EQUAL(number, 11676);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace ndn
