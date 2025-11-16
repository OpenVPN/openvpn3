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

#pragma once

namespace openvpn {

struct tls_cipher_name_pair
{
    const char *openssl_name;
    const char *iana_name;
};

/**
 * SSL/TLS Cipher suite name translation table
 */
// clang-format off
static const tls_cipher_name_pair tls_cipher_name_translation_table[] = {
    {.openssl_name = "ADH-SEED-SHA",                   .iana_name = "TLS-DH-anon-WITH-SEED-CBC-SHA"                },
    {.openssl_name = "AES128-GCM-SHA256",              .iana_name = "TLS-RSA-WITH-AES-128-GCM-SHA256"              },
    {.openssl_name = "AES128-SHA256",                  .iana_name = "TLS-RSA-WITH-AES-128-CBC-SHA256"              },
    {.openssl_name = "AES128-SHA",                     .iana_name = "TLS-RSA-WITH-AES-128-CBC-SHA"                 },
    {.openssl_name = "AES256-GCM-SHA384",              .iana_name = "TLS-RSA-WITH-AES-256-GCM-SHA384"              },
    {.openssl_name = "AES256-SHA256",                  .iana_name = "TLS-RSA-WITH-AES-256-CBC-SHA256"              },
    {.openssl_name = "AES256-SHA",                     .iana_name = "TLS-RSA-WITH-AES-256-CBC-SHA"                 },
    {.openssl_name = "CAMELLIA128-SHA256",             .iana_name = "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256"         },
    {.openssl_name = "CAMELLIA128-SHA",                .iana_name = "TLS-RSA-WITH-CAMELLIA-128-CBC-SHA"            },
    {.openssl_name = "CAMELLIA256-SHA256",             .iana_name = "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256"         },
    {.openssl_name = "CAMELLIA256-SHA",                .iana_name = "TLS-RSA-WITH-CAMELLIA-256-CBC-SHA"            },
    {.openssl_name = "DES-CBC3-SHA",                   .iana_name = "TLS-RSA-WITH-3DES-EDE-CBC-SHA"                },
    {.openssl_name = "DES-CBC-SHA",                    .iana_name = "TLS-RSA-WITH-DES-CBC-SHA"                     },
    {.openssl_name = "DH-DSS-SEED-SHA",                .iana_name = "TLS-DH-DSS-WITH-SEED-CBC-SHA"                 },
    {.openssl_name = "DHE-DSS-AES128-GCM-SHA256",      .iana_name = "TLS-DHE-DSS-WITH-AES-128-GCM-SHA256"          },
    {.openssl_name = "DHE-DSS-AES128-SHA256",          .iana_name = "TLS-DHE-DSS-WITH-AES-128-CBC-SHA256"          },
    {.openssl_name = "DHE-DSS-AES128-SHA",             .iana_name = "TLS-DHE-DSS-WITH-AES-128-CBC-SHA"             },
    {.openssl_name = "DHE-DSS-AES256-GCM-SHA384",      .iana_name = "TLS-DHE-DSS-WITH-AES-256-GCM-SHA384"          },
    {.openssl_name = "DHE-DSS-AES256-SHA256",          .iana_name = "TLS-DHE-DSS-WITH-AES-256-CBC-SHA256"          },
    {.openssl_name = "DHE-DSS-AES256-SHA",             .iana_name = "TLS-DHE-DSS-WITH-AES-256-CBC-SHA"             },
    {.openssl_name = "DHE-DSS-CAMELLIA128-SHA256",     .iana_name = "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256"     },
    {.openssl_name = "DHE-DSS-CAMELLIA128-SHA",        .iana_name = "TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA"        },
    {.openssl_name = "DHE-DSS-CAMELLIA256-SHA256",     .iana_name = "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256"     },
    {.openssl_name = "DHE-DSS-CAMELLIA256-SHA",        .iana_name = "TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA"        },
    {.openssl_name = "DHE-DSS-SEED-SHA",               .iana_name = "TLS-DHE-DSS-WITH-SEED-CBC-SHA"                },
    {.openssl_name = "DHE-RSA-AES128-GCM-SHA256",      .iana_name = "TLS-DHE-RSA-WITH-AES-128-GCM-SHA256"          },
    {.openssl_name = "DHE-RSA-AES128-SHA256",          .iana_name = "TLS-DHE-RSA-WITH-AES-128-CBC-SHA256"          },
    {.openssl_name = "DHE-RSA-AES128-SHA",             .iana_name = "TLS-DHE-RSA-WITH-AES-128-CBC-SHA"             },
    {.openssl_name = "DHE-RSA-AES256-GCM-SHA384",      .iana_name = "TLS-DHE-RSA-WITH-AES-256-GCM-SHA384"          },
    {.openssl_name = "DHE-RSA-AES256-SHA256",          .iana_name = "TLS-DHE-RSA-WITH-AES-256-CBC-SHA256"          },
    {.openssl_name = "DHE-RSA-AES256-SHA",             .iana_name = "TLS-DHE-RSA-WITH-AES-256-CBC-SHA"             },
    {.openssl_name = "DHE-RSA-CAMELLIA128-SHA256",     .iana_name = "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256"     },
    {.openssl_name = "DHE-RSA-CAMELLIA128-SHA",        .iana_name = "TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA"        },
    {.openssl_name = "DHE-RSA-CAMELLIA256-SHA256",     .iana_name = "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256"     },
    {.openssl_name = "DHE-RSA-CAMELLIA256-SHA",        .iana_name = "TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA"        },
    {.openssl_name = "DHE-RSA-CHACHA20-POLY1305",      .iana_name = "TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256"    },
    {.openssl_name = "DHE-RSA-SEED-SHA",               .iana_name = "TLS-DHE-RSA-WITH-SEED-CBC-SHA"                },
    {.openssl_name = "DH-RSA-SEED-SHA",                .iana_name = "TLS-DH-RSA-WITH-SEED-CBC-SHA"                 },
    {.openssl_name = "ECDH-ECDSA-AES128-GCM-SHA256",   .iana_name = "TLS-ECDH-ECDSA-WITH-AES-128-GCM-SHA256"       },
    {.openssl_name = "ECDH-ECDSA-AES128-SHA256",       .iana_name = "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256"       },
    {.openssl_name = "ECDH-ECDSA-AES128-SHA",          .iana_name = "TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA"          },
    {.openssl_name = "ECDH-ECDSA-AES256-GCM-SHA384",   .iana_name = "TLS-ECDH-ECDSA-WITH-AES-256-GCM-SHA384"       },
    {.openssl_name = "ECDH-ECDSA-AES256-SHA256",       .iana_name = "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA256"       },
    {.openssl_name = "ECDH-ECDSA-AES256-SHA384",       .iana_name = "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA384"       },
    {.openssl_name = "ECDH-ECDSA-AES256-SHA",          .iana_name = "TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA"          },
    {.openssl_name = "ECDH-ECDSA-CAMELLIA128-SHA256",  .iana_name = "TLS-ECDH-ECDSA-WITH-CAMELLIA-128-CBC-SHA256"  },
    {.openssl_name = "ECDH-ECDSA-CAMELLIA128-SHA",     .iana_name = "TLS-ECDH-ECDSA-WITH-CAMELLIA-128-CBC-SHA"     },
    {.openssl_name = "ECDH-ECDSA-CAMELLIA256-SHA256",  .iana_name = "TLS-ECDH-ECDSA-WITH-CAMELLIA-256-CBC-SHA256"  },
    {.openssl_name = "ECDH-ECDSA-CAMELLIA256-SHA",     .iana_name = "TLS-ECDH-ECDSA-WITH-CAMELLIA-256-CBC-SHA"     },
    {.openssl_name = "ECDH-ECDSA-DES-CBC3-SHA",        .iana_name = "TLS-ECDH-ECDSA-WITH-3DES-EDE-CBC-SHA"         },
    {.openssl_name = "ECDH-ECDSA-DES-CBC-SHA",         .iana_name = "TLS-ECDH-ECDSA-WITH-DES-CBC-SHA"              },
    {.openssl_name = "ECDH-ECDSA-RC4-SHA",             .iana_name = "TLS-ECDH-ECDSA-WITH-RC4-128-SHA"              },
    {.openssl_name = "ECDHE-ECDSA-AES128-GCM-SHA256",  .iana_name = "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"      },
    {.openssl_name = "ECDHE-ECDSA-AES128-SHA256",      .iana_name = "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256"      },
    {.openssl_name = "ECDHE-ECDSA-AES128-SHA384",      .iana_name = "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA384"      },
    {.openssl_name = "ECDHE-ECDSA-AES128-SHA",         .iana_name = "TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA"         },
    {.openssl_name = "ECDHE-ECDSA-AES256-GCM-SHA384",  .iana_name = "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"      },
    {.openssl_name = "ECDHE-ECDSA-AES256-SHA256",      .iana_name = "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA256"      },
    {.openssl_name = "ECDHE-ECDSA-AES256-SHA384",      .iana_name = "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384"      },
    {.openssl_name = "ECDHE-ECDSA-AES256-SHA",         .iana_name = "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA"         },
    {.openssl_name = "ECDHE-ECDSA-CAMELLIA128-SHA256", .iana_name = "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256" },
    {.openssl_name = "ECDHE-ECDSA-CAMELLIA128-SHA",    .iana_name = "TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA"    },
    {.openssl_name = "ECDHE-ECDSA-CAMELLIA256-SHA256", .iana_name = "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA256" },
    {.openssl_name = "ECDHE-ECDSA-CAMELLIA256-SHA",    .iana_name = "TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA"    },
    {.openssl_name = "ECDHE-ECDSA-CHACHA20-POLY1305",  .iana_name = "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256"},
    {.openssl_name = "ECDHE-ECDSA-DES-CBC3-SHA",       .iana_name = "TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA"        },
    {.openssl_name = "ECDHE-ECDSA-DES-CBC-SHA",        .iana_name = "TLS-ECDHE-ECDSA-WITH-DES-CBC-SHA"             },
    {.openssl_name = "ECDHE-ECDSA-RC4-SHA",            .iana_name = "TLS-ECDHE-ECDSA-WITH-RC4-128-SHA"             },
    {.openssl_name = "ECDHE-RSA-AES128-GCM-SHA256",    .iana_name = "TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"        },
    {.openssl_name = "ECDHE-RSA-AES128-SHA256",        .iana_name = "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"        },
    {.openssl_name = "ECDHE-RSA-AES128-SHA384",        .iana_name = "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA384"        },
    {.openssl_name = "ECDHE-RSA-AES128-SHA",           .iana_name = "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA"           },
    {.openssl_name = "ECDHE-RSA-AES256-GCM-SHA384",    .iana_name = "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"        },
    {.openssl_name = "ECDHE-RSA-AES256-SHA256",        .iana_name = "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA256"        },
    {.openssl_name = "ECDHE-RSA-AES256-SHA384",        .iana_name = "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384"        },
    {.openssl_name = "ECDHE-RSA-AES256-SHA",           .iana_name = "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA"           },
    {.openssl_name = "ECDHE-RSA-CAMELLIA128-SHA256",   .iana_name = "TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256"   },
    {.openssl_name = "ECDHE-RSA-CAMELLIA128-SHA",      .iana_name = "TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA"      },
    {.openssl_name = "ECDHE-RSA-CAMELLIA256-SHA256",   .iana_name = "TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA256"   },
    {.openssl_name = "ECDHE-RSA-CAMELLIA256-SHA",      .iana_name = "TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA"      },
    {.openssl_name = "ECDHE-RSA-CHACHA20-POLY1305",    .iana_name = "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256"  },
    {.openssl_name = "ECDHE-RSA-DES-CBC3-SHA",         .iana_name = "TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA"          },
    {.openssl_name = "ECDHE-RSA-DES-CBC-SHA",          .iana_name = "TLS-ECDHE-RSA-WITH-DES-CBC-SHA"               },
    {.openssl_name = "ECDHE-RSA-RC4-SHA",              .iana_name = "TLS-ECDHE-RSA-WITH-RC4-128-SHA"               },
    {.openssl_name = "ECDH-RSA-AES128-GCM-SHA256",     .iana_name = "TLS-ECDH-RSA-WITH-AES-128-GCM-SHA256"         },
    {.openssl_name = "ECDH-RSA-AES128-SHA256",         .iana_name = "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA256"         },
    {.openssl_name = "ECDH-RSA-AES128-SHA384",         .iana_name = "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA384"         },
    {.openssl_name = "ECDH-RSA-AES128-SHA",            .iana_name = "TLS-ECDH-RSA-WITH-AES-128-CBC-SHA"            },
    {.openssl_name = "ECDH-RSA-AES256-GCM-SHA384",     .iana_name = "TLS-ECDH-RSA-WITH-AES-256-GCM-SHA384"         },
    {.openssl_name = "ECDH-RSA-AES256-SHA256",         .iana_name = "TLS-ECDH-RSA-WITH-AES-256-CBC-SHA256"         },
    {.openssl_name = "ECDH-RSA-AES256-SHA384",         .iana_name = "TLS-ECDH-RSA-WITH-AES-256-CBC-SHA384"         },
    {.openssl_name = "ECDH-RSA-AES256-SHA",            .iana_name = "TLS-ECDH-RSA-WITH-AES-256-CBC-SHA"            },
    {.openssl_name = "ECDH-RSA-CAMELLIA128-SHA256",    .iana_name = "TLS-ECDH-RSA-WITH-CAMELLIA-128-CBC-SHA256"    },
    {.openssl_name = "ECDH-RSA-CAMELLIA128-SHA",       .iana_name = "TLS-ECDH-RSA-WITH-CAMELLIA-128-CBC-SHA"       },
    {.openssl_name = "ECDH-RSA-CAMELLIA256-SHA256",    .iana_name = "TLS-ECDH-RSA-WITH-CAMELLIA-256-CBC-SHA256"    },
    {.openssl_name = "ECDH-RSA-CAMELLIA256-SHA",       .iana_name = "TLS-ECDH-RSA-WITH-CAMELLIA-256-CBC-SHA"       },
    {.openssl_name = "ECDH-RSA-DES-CBC3-SHA",          .iana_name = "TLS-ECDH-RSA-WITH-3DES-EDE-CBC-SHA"           },
    {.openssl_name = "ECDH-RSA-DES-CBC-SHA",           .iana_name = "TLS-ECDH-RSA-WITH-DES-CBC-SHA"                },
    {.openssl_name = "ECDH-RSA-RC4-SHA",               .iana_name = "TLS-ECDH-RSA-WITH-RC4-128-SHA"                },
    {.openssl_name = "EDH-DSS-DES-CBC3-SHA",           .iana_name = "TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA"            },
    {.openssl_name = "EDH-DSS-DES-CBC-SHA",            .iana_name = "TLS-DHE-DSS-WITH-DES-CBC-SHA"                 },
    {.openssl_name = "EDH-RSA-DES-CBC3-SHA",           .iana_name = "TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA"            },
    {.openssl_name = "EDH-RSA-DES-CBC-SHA",            .iana_name = "TLS-DHE-RSA-WITH-DES-CBC-SHA"                 },
    {.openssl_name = "EXP-DES-CBC-SHA",                .iana_name = "TLS-RSA-EXPORT-WITH-DES40-CBC-SHA"            },
    {.openssl_name = "EXP-EDH-DSS-DES-CBC-SHA",        .iana_name = "TLS-DH-DSS-EXPORT-WITH-DES40-CBC-SHA"         },
    {.openssl_name = "EXP-EDH-RSA-DES-CBC-SHA",        .iana_name = "TLS-DH-RSA-EXPORT-WITH-DES40-CBC-SHA"         },
    {.openssl_name = "EXP-RC2-CBC-MD5",                .iana_name = "TLS-RSA-EXPORT-WITH-RC2-CBC-40-MD5"           },
    {.openssl_name = "EXP-RC4-MD5",                    .iana_name = "TLS-RSA-EXPORT-WITH-RC4-40-MD5"               },
    {.openssl_name = "NULL-MD5",                       .iana_name = "TLS-RSA-WITH-NULL-MD5"                        },
    {.openssl_name = "NULL-SHA256",                    .iana_name = "TLS-RSA-WITH-NULL-SHA256"                     },
    {.openssl_name = "NULL-SHA",                       .iana_name = "TLS-RSA-WITH-NULL-SHA"                        },
    {.openssl_name = "PSK-3DES-EDE-CBC-SHA",           .iana_name = "TLS-PSK-WITH-3DES-EDE-CBC-SHA"                },
    {.openssl_name = "PSK-AES128-CBC-SHA",             .iana_name = "TLS-PSK-WITH-AES-128-CBC-SHA"                 },
    {.openssl_name = "PSK-AES256-CBC-SHA",             .iana_name = "TLS-PSK-WITH-AES-256-CBC-SHA"                 },
    {.openssl_name = "PSK-RC4-SHA",                    .iana_name = "TLS-PSK-WITH-RC4-128-SHA"                     },
    {.openssl_name = "RC4-MD5",                        .iana_name = "TLS-RSA-WITH-RC4-128-MD5"                     },
    {.openssl_name = "RC4-SHA",                        .iana_name = "TLS-RSA-WITH-RC4-128-SHA"                     },
    {.openssl_name = "SEED-SHA",                       .iana_name = "TLS-RSA-WITH-SEED-CBC-SHA"                    },
    {.openssl_name = "SRP-DSS-3DES-EDE-CBC-SHA",       .iana_name = "TLS-SRP-SHA-DSS-WITH-3DES-EDE-CBC-SHA"        },
    {.openssl_name = "SRP-DSS-AES-128-CBC-SHA",        .iana_name = "TLS-SRP-SHA-DSS-WITH-AES-128-CBC-SHA"         },
    {.openssl_name = "SRP-DSS-AES-256-CBC-SHA",        .iana_name = "TLS-SRP-SHA-DSS-WITH-AES-256-CBC-SHA"         },
    {.openssl_name = "SRP-RSA-3DES-EDE-CBC-SHA",       .iana_name = "TLS-SRP-SHA-RSA-WITH-3DES-EDE-CBC-SHA"        },
    {.openssl_name = "SRP-RSA-AES-128-CBC-SHA",        .iana_name = "TLS-SRP-SHA-RSA-WITH-AES-128-CBC-SHA"         },
    {.openssl_name = "SRP-RSA-AES-256-CBC-SHA",        .iana_name = "TLS-SRP-SHA-RSA-WITH-AES-256-CBC-SHA"         }
};
// clang-format on

inline const tls_cipher_name_pair *
tls_get_cipher_name_pair(const std::string &ciphername)
{
    for (auto &pair : tls_cipher_name_translation_table)
    {
        if (pair.iana_name == ciphername || pair.openssl_name == ciphername)
            return &pair;
    }

    /* No entry found, return NULL */
    return NULL;
}
} // namespace openvpn