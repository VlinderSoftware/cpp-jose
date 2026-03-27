/// @file jose.cpp
/// @brief jose CLI — git-style command dispatcher for the cpp-jose library.
///
/// Usage:
///   jose <command> <subcommand> [options] [FILE|-]
///
/// Commands:
///   jose jwk  generate|inspect|thumbprint
///   jose jws  sign|verify|inspect
///   jose jwe  encrypt|decrypt|inspect
///   jose jwt  sign|verify|inspect

#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "jose/jose.hpp"

using namespace std;
using namespace Vlinder::JOSE;

// ─── I/O helpers ─────────────────────────────────────────────────────────────

static string readStream(istream &in)
{
    return {istreambuf_iterator<char>(in), {}};
}

static string readInput(string const &path)
{
    if (path == "-")
        return readStream(cin);
    ifstream f(path);
    if (!f)
        throw runtime_error("Cannot open file: " + path);
    return readStream(f);
}

static string trim(string s)
{
    auto first = s.find_first_not_of(" \t\n\r");
    if (first == string::npos)
        return {};
    auto last = s.find_last_not_of(" \t\n\r");
    return s.substr(first, last - first + 1);
}

// ─── Argument parser ─────────────────────────────────────────────────────────
/// Minimal git-style argument parser.
///   --key value      → opts["key"] = {"value"}
///   --flag           → flags
///   positional       → positional
/// Multi-value: --claim a=b --claim c=d → opts["claim"] = {"a=b", "c=d"}
struct Args
{
    map<string, vector<string>> opts;
    set<string> flags;
    vector<string> positional;

    static Args parse(int argc, char const *const *argv, int start = 0)
    {
        Args a;
        for (int i = start; i < argc; ++i)
        {
            string arg = argv[i];
            if (arg.size() > 2 && arg[0] == '-' && arg[1] == '-')
            {
                string key = arg.substr(2);
                // Treat as option if the next token doesn't look like a flag
                if (i + 1 < argc && argv[i + 1][0] != '-')
                {
                    a.opts[key].push_back(argv[++i]);
                }
                else
                {
                    a.flags.insert(key);
                }
            }
            else if (!arg.empty() && arg[0] != '-')
            {
                a.positional.push_back(arg);
            }
        }
        return a;
    }

    /// Return the last value for a key, or the default.
    string get(string const &key, string const &def = {}) const
    {
        auto it = opts.find(key);
        if (it == opts.end() || it->second.empty())
            return def;
        return it->second.back();
    }

    /// Return all values for a key (for multi-value flags like --claim).
    vector<string> getAll(string const &key) const
    {
        auto it = opts.find(key);
        return it != opts.end() ? it->second : vector<string>{};
    }

    bool has(string const &key) const
    {
        return flags.count(key) > 0 || opts.count(key) > 0;
    }

    string require(string const &key) const
    {
        string v = get(key);
        if (v.empty())
            throw runtime_error("Missing required option --" + key);
        return v;
    }

    /// Positional input file; "-" means stdin.
    string input() const
    {
        return positional.empty() ? "-" : positional[0];
    }
};

// ─── Algorithm name maps ──────────────────────────────────────────────────────

static map<string, JWA::SignatureAlgorithm> const kSigAlgs = {
    {"HS256", JWA::SignatureAlgorithm::hs256},
    {"HS384", JWA::SignatureAlgorithm::hs384},
    {"HS512", JWA::SignatureAlgorithm::hs512},
    {"RS256", JWA::SignatureAlgorithm::rs256},
    {"RS384", JWA::SignatureAlgorithm::rs384},
    {"RS512", JWA::SignatureAlgorithm::rs512},
    {"ES256", JWA::SignatureAlgorithm::es256},
    {"ES384", JWA::SignatureAlgorithm::es384},
    {"ES512", JWA::SignatureAlgorithm::es512},
    {"PS256", JWA::SignatureAlgorithm::ps256},
    {"PS384", JWA::SignatureAlgorithm::ps384},
    {"PS512", JWA::SignatureAlgorithm::ps512},
    {"none",  JWA::SignatureAlgorithm::none},
};

static map<string, JWA::KeyEncryptionAlgorithm> const kKea = {
    {"RSA1_5",       JWA::KeyEncryptionAlgorithm::rsa1_5},
    {"RSA-OAEP",     JWA::KeyEncryptionAlgorithm::rsa_oaep},
    {"RSA-OAEP-256", JWA::KeyEncryptionAlgorithm::rsa_oaep_256},
    {"A128KW",       JWA::KeyEncryptionAlgorithm::a128kw},
    {"A192KW",       JWA::KeyEncryptionAlgorithm::a192kw},
    {"A256KW",       JWA::KeyEncryptionAlgorithm::a256kw},
    {"dir",          JWA::KeyEncryptionAlgorithm::dir},
    {"ECDH-ES",      JWA::KeyEncryptionAlgorithm::ecdh_es},
    {"A128GCMKW",    JWA::KeyEncryptionAlgorithm::a128gcmkw},
    {"A192GCMKW",    JWA::KeyEncryptionAlgorithm::a192gcmkw},
    {"A256GCMKW",    JWA::KeyEncryptionAlgorithm::a256gcmkw},
};

static map<string, JWA::ContentEncryptionAlgorithm> const kCea = {
    {"A128CBC-HS256", JWA::ContentEncryptionAlgorithm::a128cbc_hs256},
    {"A192CBC-HS384", JWA::ContentEncryptionAlgorithm::a192cbc_hs384},
    {"A256CBC-HS512", JWA::ContentEncryptionAlgorithm::a256cbc_hs512},
    {"A128GCM",       JWA::ContentEncryptionAlgorithm::a128gcm},
    {"A192GCM",       JWA::ContentEncryptionAlgorithm::a192gcm},
    {"A256GCM",       JWA::ContentEncryptionAlgorithm::a256gcm},
};

// ─── jose jwk ─────────────────────────────────────────────────────────────────

static int cmdJwkGenerate(Args const &args)
{
    string type  = args.get("type", "ec");
    string use_s = args.get("use", "sig");
    string alg   = args.get("alg");
    string kid   = args.get("kid");
    bool priv    = args.has("private");

    JWK::Use use = (use_s == "enc") ? JWK::Use::encryption : JWK::Use::signature;

    JWK key = [=]() -> JWK
    {
        if (type == "rsa")
        {
            int bits = stoi(args.get("bits", "2048"));
            return JWK::generateRSA(use, static_cast<unsigned int>(bits), alg);
        }
        if (type == "ec")
        {
            string curve = args.get("curve", "P-256");
            return JWK::generateEC(use, curve, alg);
        }
        if (type == "oct")
        {
            int bits = stoi(args.get("bits", "256"));
            return JWK::generateOct(use, bits, alg);
        }
        if (type == "okp")
        {
            return JWK::generateOKP(use, 0, alg);
        }
        throw runtime_error("Unknown key type: " + type + "  (rsa|ec|oct|okp)");
    }();

    if (!kid.empty())
        key.setKeyID(kid);

    cout << key.toJSON(priv) << "\n";
    return 0;
}

static int cmdJwkInspect(Args const &args)
{
    bool priv      = args.has("private");
    string json    = trim(readInput(args.input()));
    JWK key        = JWK::fromJSON(json);

    string type_s;
    switch (key.getKeyType())
    {
        case JWK::KeyType::rsa: type_s = "RSA"; break;
        case JWK::KeyType::ec:  type_s = "EC";  break;
        case JWK::KeyType::oct: type_s = "oct"; break;
        case JWK::KeyType::okp: type_s = "OKP"; break;
    }

    cout << "kty : " << type_s << "\n"
         << "kid : " << key.getKeyID() << "\n"
         << "alg : " << key.getAlgorithm() << "\n"
         << "priv: " << (key.hasPrivateKey() ? "yes" : "no") << "\n"
         << "\n"
         << key.toJSON(priv && key.hasPrivateKey()) << "\n";
    return 0;
}

static int cmdJwkThumbprint(Args const &args)
{
    string json = trim(readInput(args.input()));
    JWK key     = JWK::fromJSON(json);
    cout << key.getKeyID() << "\n";
    return 0;
}

static void helpJwk()
{
    cerr <<
        "Usage: jose jwk <subcommand> [options] [FILE|-]\n"
        "\n"
        "Subcommands:\n"
        "  generate   Generate a new JWK and write JSON to stdout\n"
        "  inspect    Show key metadata and JSON\n"
        "  thumbprint Print the key thumbprint (kid)\n"
        "\n"
        "generate options:\n"
        "  --type  rsa|ec|oct|okp  (default: ec)\n"
        "  --bits  N               Key size in bits (RSA/oct)\n"
        "  --curve P-256|P-384|P-521 (default: P-256, EC only)\n"
        "  --use   sig|enc         (default: sig)\n"
        "  --alg   ALGORITHM       Optional algorithm hint\n"
        "  --kid   ID              Key ID (default: thumbprint)\n"
        "  --private               Include private key material in output\n"
        "\n"
        "inspect options:\n"
        "  --private  Include private key material in output\n";
}

static int cmdJwk(int argc, char const *const *argv)
{
    if (argc < 1)
    {
        helpJwk();
        return 1;
    }
    string sub = argv[0];
    Args args  = Args::parse(argc, argv, 1);

    if (sub == "generate")
        return cmdJwkGenerate(args);
    if (sub == "inspect")
        return cmdJwkInspect(args);
    if (sub == "thumbprint")
        return cmdJwkThumbprint(args);

    cerr << "Unknown subcommand: jose jwk " << sub << "\n";
    helpJwk();
    return 1;
}

// ─── jose jws ─────────────────────────────────────────────────────────────────

static int cmdJwsSign(Args const &args)
{
    string alg_s   = args.require("alg");
    string key_src = args.require("key");
    string payload = readInput(args.input());

    auto it = kSigAlgs.find(alg_s);
    if (it == kSigAlgs.end())
        throw runtime_error("Unknown signature algorithm: " + alg_s);

    JWK key = JWK::fromJSON(trim(readInput(key_src)));

    JWS jws;
    jws.setPayload(payload);
    jws.setAlgorithm(it->second);

    if (string kid = args.get("kid"); !kid.empty())
        jws.setKeyID(kid);
    if (string typ = args.get("typ"); !typ.empty())
        jws.setType(typ);

    cout << jws.sign(key) << "\n";
    return 0;
}

static int cmdJwsVerify(Args const &args)
{
    string key_src = args.require("key");
    string token   = trim(readInput(args.input()));

    JWK key = JWK::fromJSON(trim(readInput(key_src)));

    if (!JWS::verify(token, key))
    {
        cerr << "Signature verification FAILED\n";
        return 1;
    }
    cerr << "Signature OK\n";
    return 0;
}

static int cmdJwsInspect(Args const &args)
{
    string token = trim(readInput(args.input()));
    JWS jws      = JWS::parse(token);

    cout << "header : " << jws.getHeader() << "\n"
         << "payload: " << jws.getPayload() << "\n";
    return 0;
}

static void helpJws()
{
    cerr <<
        "Usage: jose jws <subcommand> [options] [FILE|-]\n"
        "\n"
        "Subcommands:\n"
        "  sign     Sign a payload and output a compact JWS\n"
        "  verify   Verify a compact JWS signature\n"
        "  inspect  Decode and display header and payload (no verification)\n"
        "\n"
        "sign options:\n"
        "  --key FILE   JWK key file (required)\n"
        "  --alg ALG    Algorithm: HS256|RS256|ES256|PS256|...  (required)\n"
        "  --kid ID     Key ID to embed in header\n"
        "  --typ TYPE   typ header (e.g. JWT)\n"
        "\n"
        "verify options:\n"
        "  --key FILE   JWK key file (required)\n";
}

static int cmdJws(int argc, char const *const *argv)
{
    if (argc < 1)
    {
        helpJws();
        return 1;
    }
    string sub = argv[0];
    Args args  = Args::parse(argc, argv, 1);

    if (sub == "sign")
        return cmdJwsSign(args);
    if (sub == "verify")
        return cmdJwsVerify(args);
    if (sub == "inspect")
        return cmdJwsInspect(args);

    cerr << "Unknown subcommand: jose jws " << sub << "\n";
    helpJws();
    return 1;
}

// ─── jose jwe ─────────────────────────────────────────────────────────────────

static int cmdJweEncrypt(Args const &args)
{
    string alg_s   = args.require("alg");
    string enc_s   = args.require("enc");
    string key_src = args.require("key");
    string plain   = readInput(args.input());

    auto kit = kKea.find(alg_s);
    if (kit == kKea.end())
        throw runtime_error("Unknown key encryption algorithm: " + alg_s);

    auto eit = kCea.find(enc_s);
    if (eit == kCea.end())
        throw runtime_error("Unknown content encryption algorithm: " + enc_s);

    JWK key = JWK::fromJSON(trim(readInput(key_src)));

    JWE jwe;
    jwe.setPlaintext(plain);
    jwe.setKeyEncryptionAlgorithm(kit->second);
    jwe.setContentEncryptionAlgorithm(eit->second);

    if (string kid = args.get("kid"); !kid.empty())
        jwe.setKeyID(kid);
    if (string typ = args.get("typ"); !typ.empty())
        jwe.setType(typ);

    cout << jwe.encrypt(key) << "\n";
    return 0;
}

static int cmdJweDecrypt(Args const &args)
{
    string key_src = args.require("key");
    string token   = trim(readInput(args.input()));

    JWK key = JWK::fromJSON(trim(readInput(key_src)));
    cout << JWE::decrypt(token, key);
    return 0;
}

static int cmdJweInspect(Args const &args)
{
    // Decode the protected header segment without decryption.
    string token = trim(readInput(args.input()));
    auto dot     = token.find('.');
    if (dot == string::npos)
        throw runtime_error("Invalid JWE compact token: no '.' separator found");

    string header_json = Base64URL::decodeToString(token.substr(0, dot));
    cout << header_json << "\n";
    return 0;
}

static void helpJwe()
{
    cerr <<
        "Usage: jose jwe <subcommand> [options] [FILE|-]\n"
        "\n"
        "Subcommands:\n"
        "  encrypt  Encrypt plaintext and output a compact JWE\n"
        "  decrypt  Decrypt a compact JWE\n"
        "  inspect  Decode and display the protected header (no decryption)\n"
        "\n"
        "encrypt options:\n"
        "  --key FILE   JWK key file (required)\n"
        "  --alg ALG    Key encryption: RSA-OAEP|RSA-OAEP-256|A128KW|A256KW|dir|ECDH-ES|A128GCMKW|...  (required)\n"
        "  --enc ENC    Content encryption: A128GCM|A256GCM|A128CBC-HS256|A256CBC-HS512|...  (required)\n"
        "  --kid ID     Key ID to embed in header\n"
        "\n"
        "decrypt options:\n"
        "  --key FILE   JWK key file with private material (required)\n";
}

static int cmdJwe(int argc, char const *const *argv)
{
    if (argc < 1)
    {
        helpJwe();
        return 1;
    }
    string sub = argv[0];
    Args args  = Args::parse(argc, argv, 1);

    if (sub == "encrypt")
        return cmdJweEncrypt(args);
    if (sub == "decrypt")
        return cmdJweDecrypt(args);
    if (sub == "inspect")
        return cmdJweInspect(args);

    cerr << "Unknown subcommand: jose jwe " << sub << "\n";
    helpJwe();
    return 1;
}

// ─── jose jwt ─────────────────────────────────────────────────────────────────

static int cmdJwtSign(Args const &args)
{
    string key_src = args.require("key");
    string alg_s   = args.get("alg", "RS256");

    JWK key = JWK::fromJSON(trim(readInput(key_src)));

    JWT jwt;

    if (string v = args.get("iss"); !v.empty())
        jwt.setIssuer(v);
    if (string v = args.get("sub"); !v.empty())
        jwt.setSubject(v);
    if (string v = args.get("aud"); !v.empty())
        jwt.setAudience(v);
    if (string v = args.get("jti"); !v.empty())
        jwt.setJWTID(v);

    auto now = chrono::system_clock::now();
    if (string v = args.get("exp"); !v.empty())
        jwt.setExpiration(now + chrono::seconds(stoi(v)));
    if (string v = args.get("nbf"); !v.empty())
        jwt.setNotBefore(now + chrono::seconds(stoi(v)));
    if (args.has("iat"))
        jwt.setIssuedAt(now);

    for (string const &pair : args.getAll("claim"))
    {
        auto eq = pair.find('=');
        if (eq == string::npos)
            throw runtime_error("--claim must be in k=v format, got: " + pair);
        jwt.setClaim(pair.substr(0, eq), pair.substr(eq + 1));
    }

    cout << jwt.sign(key, alg_s) << "\n";
    return 0;
}

static int cmdJwtVerify(Args const &args)
{
    string key_src = args.require("key");
    string token   = trim(readInput(args.input()));

    JWK key = JWK::fromJSON(trim(readInput(key_src)));

    JWT jwt = JWT::verify(token, key);  // throws on bad signature

    string iss    = args.get("iss");
    string aud    = args.get("aud");
    int leeway    = stoi(args.get("leeway", "0"));

    bool ok = jwt.validate(iss, aud, leeway);
    if (!ok)
    {
        cerr << "JWT claims validation FAILED\n";
        return 1;
    }

    // Print claims to stdout
    cerr << "Signature and claims OK\n";

    cout << "iss: " << jwt.getIssuer()  << "\n"
         << "sub: " << jwt.getSubject() << "\n"
         << "jti: " << jwt.getJWTID()   << "\n";

    for (string const &aud_val : jwt.getAudience())
        cout << "aud: " << aud_val << "\n";

    return 0;
}

static int cmdJwtInspect(Args const &args)
{
    string token = trim(readInput(args.input()));
    JWT jwt      = JWT::parse(token);

    // Decode the raw payload for a complete view of all claims
    auto dot1 = token.find('.');
    auto dot2 = (dot1 != string::npos) ? token.find('.', dot1 + 1) : string::npos;
    if (dot1 != string::npos && dot2 != string::npos)
    {
        string raw_payload = Base64URL::decodeToString(token.substr(dot1 + 1, dot2 - dot1 - 1));
        cout << "payload: " << raw_payload << "\n\n";
    }

    // Print registered claims in human-readable form
    if (!jwt.getIssuer().empty())  cout << "iss: " << jwt.getIssuer()  << "\n";
    if (!jwt.getSubject().empty()) cout << "sub: " << jwt.getSubject() << "\n";
    if (!jwt.getJWTID().empty())   cout << "jti: " << jwt.getJWTID()   << "\n";

    for (string const &aud_val : jwt.getAudience())
        cout << "aud: " << aud_val << "\n";

    auto printTime = [](string const &label, chrono::system_clock::time_point tp)
    {
        auto t = chrono::system_clock::to_time_t(tp);
        if (t == 0)
            return;
        char buf[32];
        struct tm tm_buf{};
#if defined(_WIN32)
        gmtime_s(&tm_buf, &t);
#else
        gmtime_r(&t, &tm_buf);
#endif
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
        cout << label << ": " << buf << "\n";
    };

    printTime("iat", jwt.getIssuedAt());
    printTime("nbf", jwt.getNotBefore());
    printTime("exp", jwt.getExpiration());

    return 0;
}

static void helpJwt()
{
    cerr <<
        "Usage: jose jwt <subcommand> [options] [FILE|-]\n"
        "\n"
        "Subcommands:\n"
        "  sign     Create and sign a JWT\n"
        "  verify   Verify signature and validate claims\n"
        "  inspect  Decode and display claims (no verification)\n"
        "\n"
        "sign options:\n"
        "  --key FILE       JWK key file (required)\n"
        "  --alg ALG        Algorithm (default: RS256)\n"
        "  --iss ISSUER     iss claim\n"
        "  --sub SUBJECT    sub claim\n"
        "  --aud AUDIENCE   aud claim\n"
        "  --exp SECONDS    exp claim: seconds from now\n"
        "  --nbf SECONDS    nbf claim: seconds from now\n"
        "  --iat            Set iat to current time\n"
        "  --jti ID         jti claim\n"
        "  --claim k=v      Custom claim (repeatable)\n"
        "\n"
        "verify options:\n"
        "  --key FILE       JWK key file (required)\n"
        "  --iss ISSUER     Expected issuer\n"
        "  --aud AUDIENCE   Expected audience\n"
        "  --leeway N       Clock skew tolerance in seconds (default: 0)\n";
}

static int cmdJwt(int argc, char const *const *argv)
{
    if (argc < 1)
    {
        helpJwt();
        return 1;
    }
    string sub = argv[0];
    Args args  = Args::parse(argc, argv, 1);

    if (sub == "sign")
        return cmdJwtSign(args);
    if (sub == "verify")
        return cmdJwtVerify(args);
    if (sub == "inspect")
        return cmdJwtInspect(args);

    cerr << "Unknown subcommand: jose jwt " << sub << "\n";
    helpJwt();
    return 1;
}

// ─── Top-level dispatch ───────────────────────────────────────────────────────

static void helpTop()
{
    cerr <<
        "jose — command-line interface for cpp-jose\n"
        "\n"
        "Usage: jose <command> [subcommand] [options] [FILE|-]\n"
        "\n"
        "Commands:\n"
        "  jwk   JSON Web Key management\n"
        "  jws   JSON Web Signature sign/verify\n"
        "  jwe   JSON Web Encryption encrypt/decrypt\n"
        "  jwt   JSON Web Token create/verify/inspect\n"
        "\n"
        "Run 'jose <command>' with no subcommand for per-command help.\n"
        "\n"
        "Input is read from FILE or stdin ('-') when not otherwise supplied.\n"
        "Key material is always read from a file via --key (use '-' for stdin).\n";
}

int main(int argc, char const *argv[])
{
    if (argc < 2)
    {
        helpTop();
        return 1;
    }

    string cmd = argv[1];

    try
    {
        if (cmd == "jwk")
            return cmdJwk(argc - 2, argv + 2);
        if (cmd == "jws")
            return cmdJws(argc - 2, argv + 2);
        if (cmd == "jwe")
            return cmdJwe(argc - 2, argv + 2);
        if (cmd == "jwt")
            return cmdJwt(argc - 2, argv + 2);

        cerr << "Unknown command: " << cmd << "\n\n";
        helpTop();
        return 1;
    }
    catch (exception const &e)
    {
        cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
