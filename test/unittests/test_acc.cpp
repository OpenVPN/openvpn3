//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//



#include "test_common.hpp"
#include <openvpn/ssl/customcontrolchannel.hpp>
#include <regex>

using namespace openvpn;

// This message has 215 bytes
const std::string messagetext = "OpenVPN -- An application to securely tunnel IP networks\n"
                                "over a single port, with support for SSL/TLS-based\n"
                                "session authentication and key exchange,\n"
                                "packet encryption, packet authentication, and\n"
                                "packet compression.";

static AppControlMessageConfig genACMC()
{
    AppControlMessageConfig acmc;

    acmc.supported_protocols = {"foo", "flower"};
    acmc.max_msg_size = 140;
    acmc.encoding_base64 = true;
    acmc.encoding_text = true;
    return acmc;
}

TEST(Customcontrolchannel, Msgroundtrip)
{
    auto acmc = genACMC();

    auto controlmsg = acmc.format_message("flower", messagetext);
    // \n forces base64 and should trigger three messages
    EXPECT_EQ(controlmsg.size(), 3);

    bool received;

    AppControlMessageReceiver accrecv;
    for (const auto &cmsg : controlmsg)
    {
        ASSERT_LE(cmsg.size(), 140);
        received = accrecv.receive_message(cmsg);
    }

    ASSERT_TRUE(received);

    auto [recv_proto, received_message] = accrecv.get_message();
    ASSERT_EQ(received_message, messagetext);
    ASSERT_EQ(recv_proto, "flower");
}

TEST(Customcontrolchannel, Msgroundtripascii)
{
    auto acmc = genACMC();

    // Remove special chars
    auto messagetextNoCR = std::regex_replace(messagetext, std::regex{"\n"}, "");
    auto controlmsg = acmc.format_message("flower", messagetextNoCR);

    // Should be text encoding
    EXPECT_EQ(controlmsg.size(), 2);

    bool received;
    AppControlMessageReceiver accrecv{};

    for (const auto &cmsg : controlmsg)
    {
        ASSERT_LE(cmsg.size(), 140);
        received = accrecv.receive_message(cmsg);
    }

    ASSERT_TRUE(received);
    auto [recv_proto, received_message] = accrecv.get_message();
    ASSERT_EQ(received_message, messagetextNoCR);
    ASSERT_EQ(recv_proto, "flower");
}

TEST(Customcontrolchannel, Msgroundtriponepacket)
{
    auto acmc = genACMC();

    acmc.max_msg_size = 2000;
    auto controlmsg = acmc.format_message("flower", messagetext);

    /* Should fit the whole message */
    EXPECT_EQ(controlmsg.size(), 1);

    bool received;
    AppControlMessageReceiver accrecv{};

    received = accrecv.receive_message(controlmsg.at(0));

    ASSERT_TRUE(received);
    auto [recv_proto, received_message] = accrecv.get_message();
    ASSERT_EQ(received_message, messagetext);
    ASSERT_EQ(recv_proto, "flower");
}

TEST(Customcontrolchannel, Tinymessage)
{
    std::string request{"I want a cookie!"};
    auto acmc = genACMC();
    acmc.supported_protocols.push_back("fortune");
    auto cmsgs = acmc.format_message("fortune", request);
    EXPECT_EQ(cmsgs.size(), 1);

    EXPECT_EQ(cmsgs.at(0), std::string("ACC,fortune,16,A,I want a cookie!"));
}

TEST(Customcontrolchannel, Acctostr)
{
    auto acmc = genACMC();

    auto desc = acmc.str();
    EXPECT_EQ(desc, "protocols foo flower, msg_size 140, encoding ascii base64");
}

TEST(Customcontrolchannel, RecvWithNul)
{
    std::string control_msg{"ACC,fortune,64,6,InsgIm1lIjogImZyb2ciLCAAeGZm/SJtc2ciOiAiSSBhbSAAS2VybWl0IiB9Ig=="};

    bool received = false;
    AppControlMessageReceiver accrecv{};


    received = accrecv.receive_message(control_msg);

    char data[] = "\"{ \"me\": \"frog\", \0xff\xfd\"msg\": \"I am \0Kermit\" }\"";
    const std::string expected_string{data, sizeof(data) - 1};

    ASSERT_TRUE(received);
    auto [recv_proto, received_message] = accrecv.get_message();
    ASSERT_EQ(46, received_message.length());
    ASSERT_EQ(received_message, expected_string);
    ASSERT_EQ(recv_proto, "fortune");
}

TEST(Customcontrolchannel, SendWithNul)
{
    auto acmc = genACMC();
    acmc.supported_protocols.push_back("fortune");


    char data[] = "\"{ \"me\": \"frog\", \0xff\xfd\"msg\": \"I am \0Kermit\" }\"";
    const std::string string_with_nul{data, sizeof(data) - 1};

    const auto cmsgs = acmc.format_message("fortune", string_with_nul);

    const std::string expected_control_msg{"ACC,fortune,64,6,InsgIm1lIjogImZyb2ciLCAAeGZm/SJtc2ciOiAiSSBhbSAAS2VybWl0IiB9Ig=="};

    EXPECT_EQ(cmsgs.size(), 1);
    EXPECT_EQ(cmsgs[0], expected_control_msg);
}

TEST(Customcontrolchannel, TestIncorrectLen)
{
    std::string control_msg{"ACC,fortune,62,6,InsgIm1lIjogImZyb2ciLCAAeGZm/SJtc2ciOiAiSSBhbSAAS2VybWl0IiB9Ig=="};

    AppControlMessageReceiver accrecv{};

    EXPECT_THROW(
        accrecv.receive_message(control_msg),
        parse_acc_message);
}

TEST(Customcontrolchannel, TestWrongHeader)
{
    std::string control_msg{"ABC,fortune,64,6,InsgIm1lIjogImZyb2ciLCAAeGZm/SJtc2ciOiAiSSBhbSAAS2VybWl0IiB9Ig=="};

    AppControlMessageReceiver accrecv{};

    EXPECT_THROW(
        accrecv.receive_message(control_msg),
        parse_acc_message);
}

TEST(Customcontrolchannel, TestUnsupportedEncoding)
{
    std::string control_msg{"ACC,fortune,64,Q,InsgIm1lIjogImZyb2ciLCAAeGZm/SJtc2ciOiAiSSBhbSAAS2VybWl0IiB9Ig=="};

    AppControlMessageReceiver accrecv{};

    EXPECT_THROW(
        accrecv.receive_message(control_msg),
        parse_acc_message);
}

TEST(Customcontrolchannel, TestMissingMessage)
{
    std::string control_msg{"ABC,fortune,64,6"};

    AppControlMessageReceiver accrecv{};

    EXPECT_THROW(
        accrecv.receive_message(control_msg),
        parse_acc_message);
}