#include "jose/json_utils.hpp"

#include <cctype>
#include <map>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace Vlinder {
namespace jose {

struct JsonValue::Impl
{
    Type type = Type::Null;
    bool boolValue = false;
    double numberValue = 0.0;
    std::string stringValue;
    std::vector<JsonValue> arrayValue;
    std::map<std::string, JsonValue> objectValue;
};

JsonValue::JsonValue() : impl_(std::make_shared<Impl>())
{
}

JsonValue::JsonValue(bool value) : impl_(std::make_shared<Impl>())
{
    impl_->type = Type::Boolean;
    impl_->boolValue = value;
}

JsonValue::JsonValue(int value) : impl_(std::make_shared<Impl>())
{
    impl_->type = Type::Number;
    impl_->numberValue = static_cast<double>(value);
}

JsonValue::JsonValue(double value) : impl_(std::make_shared<Impl>())
{
    impl_->type = Type::Number;
    impl_->numberValue = value;
}

JsonValue::JsonValue(const std::string& value) : impl_(std::make_shared<Impl>())
{
    impl_->type = Type::String;
    impl_->stringValue = value;
}

JsonValue::JsonValue(const char* value) : impl_(std::make_shared<Impl>())
{
    impl_->type = Type::String;
    impl_->stringValue = value;
}

JsonValue::Type JsonValue::getType() const
{
    return impl_->type;
}

bool JsonValue::isNull() const
{
    return impl_->type == Type::Null;
}
bool JsonValue::isBoolean() const
{
    return impl_->type == Type::Boolean;
}
bool JsonValue::isNumber() const
{
    return impl_->type == Type::Number;
}
bool JsonValue::isString() const
{
    return impl_->type == Type::String;
}
bool JsonValue::isArray() const
{
    return impl_->type == Type::Array;
}
bool JsonValue::isObject() const
{
    return impl_->type == Type::Object;
}

bool JsonValue::asBoolean() const
{
    if (impl_->type != Type::Boolean)
    {
        throw std::runtime_error("Not a boolean");
    }
    return impl_->boolValue;
}

double JsonValue::asNumber() const
{
    if (impl_->type != Type::Number)
    {
        throw std::runtime_error("Not a number");
    }
    return impl_->numberValue;
}

std::string JsonValue::asString() const
{
    if (impl_->type != Type::String)
    {
        throw std::runtime_error("Not a string");
    }
    return impl_->stringValue;
}

void JsonValue::setArray()
{
    impl_->type = Type::Array;
    impl_->arrayValue.clear();
}

void JsonValue::setObject()
{
    impl_->type = Type::Object;
    impl_->objectValue.clear();
}

void JsonValue::append(const JsonValue& value)
{
    if (impl_->type != Type::Array)
    {
        throw std::runtime_error("Not an array");
    }
    impl_->arrayValue.push_back(value);
}

void JsonValue::set(const std::string& key, const JsonValue& value)
{
    if (impl_->type != Type::Object)
    {
        throw std::runtime_error("Not an object");
    }
    impl_->objectValue[key] = value;
}

const JsonValue& JsonValue::operator[](size_t index) const
{
    if (impl_->type != Type::Array)
    {
        throw std::runtime_error("Not an array");
    }
    if (index >= impl_->arrayValue.size())
    {
        throw std::out_of_range("Array index out of range");
    }
    return impl_->arrayValue[index];
}

const JsonValue& JsonValue::operator[](const std::string& key) const
{
    if (impl_->type != Type::Object)
    {
        throw std::runtime_error("Not an object");
    }
    auto it = impl_->objectValue.find(key);
    if (it == impl_->objectValue.end())
    {
        static JsonValue null;
        return null;
    }
    return it->second;
}

bool JsonValue::has(const std::string& key) const
{
    if (impl_->type != Type::Object)
    {
        return false;
    }
    return impl_->objectValue.find(key) != impl_->objectValue.end();
}

static std::string escapeString(const std::string& str)
{
    std::string result;
    for (char c : str)
    {
        switch (c)
        {
            case '"':
                result += "\\\"";
                break;
            case '\\':
                result += "\\\\";
                break;
            case '\b':
                result += "\\b";
                break;
            case '\f':
                result += "\\f";
                break;
            case '\n':
                result += "\\n";
                break;
            case '\r':
                result += "\\r";
                break;
            case '\t':
                result += "\\t";
                break;
            default:
                if (static_cast<unsigned char>(c) < 0x20)
                {
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    result += buf;
                }
                else
                {
                    result += c;
                }
        }
    }
    return result;
}

std::string JsonValue::serialize() const
{
    std::ostringstream oss;

    switch (impl_->type)
    {
        case Type::Null:
            oss << "null";
            break;

        case Type::Boolean:
            oss << (impl_->boolValue ? "true" : "false");
            break;

        case Type::Number:
            if (impl_->numberValue == static_cast<int>(impl_->numberValue))
            {
                oss << static_cast<int>(impl_->numberValue);
            }
            else
            {
                oss << impl_->numberValue;
            }
            break;

        case Type::String:
            oss << '"' << escapeString(impl_->stringValue) << '"';
            break;

        case Type::Array:
            oss << '[';
            for (size_t i = 0; i < impl_->arrayValue.size(); ++i)
            {
                if (i > 0)
                {
                    oss << ',';
                }
                oss << impl_->arrayValue[i].serialize();
            }
            oss << ']';
            break;

        case Type::Object:
            oss << '{';
            bool first = true;
            for (const auto& pair : impl_->objectValue)
            {
                if (!first)
                {
                    oss << ',';
                }
                first = false;
                oss << '"' << escapeString(pair.first) << "\":" << pair.second.serialize();
            }
            oss << '}';
            break;
    }

    return oss.str();
}

// Simple JSON parser
class JsonParser
{
public:
    JsonParser(const std::string& json) : json_(json), pos_(0)
    {
    }

    JsonValue parse()
    {
        skipWhitespace();
        return parseValue();
    }

private:
    std::string json_;
    size_t pos_;

    void skipWhitespace()
    {
        while (pos_ < json_.length() && std::isspace(json_[pos_]))
        {
            ++pos_;
        }
    }

    char peek() const
    {
        return pos_ < json_.length() ? json_[pos_] : '\0';
    }

    char next()
    {
        return pos_ < json_.length() ? json_[pos_++] : '\0';
    }

    JsonValue parseValue()
    {
        skipWhitespace();
        char c = peek();

        if (c == 'n')
        {
            return parseNull();
        }
        else if (c == 't' || c == 'f')
        {
            return parseBoolean();
        }
        else if (c == '"')
        {
            return parseString();
        }
        else if (c == '[')
        {
            return parseArray();
        }
        else if (c == '{')
        {
            return parseObject();
        }
        else if (c == '-' || std::isdigit(c))
        {
            return parseNumber();
        }

        throw std::runtime_error("Invalid JSON");
    }

    JsonValue parseNull()
    {
        if (json_.substr(pos_, 4) == "null")
        {
            pos_ += 4;
            return JsonValue();
        }
        throw std::runtime_error("Invalid null");
    }

    JsonValue parseBoolean()
    {
        if (json_.substr(pos_, 4) == "true")
        {
            pos_ += 4;
            return JsonValue(true);
        }
        else if (json_.substr(pos_, 5) == "false")
        {
            pos_ += 5;
            return JsonValue(false);
        }
        throw std::runtime_error("Invalid boolean");
    }

    JsonValue parseNumber()
    {
        size_t start = pos_;
        if (peek() == '-')
        {
            next();
        }

        while (std::isdigit(peek()))
        {
            next();
        }

        if (peek() == '.')
        {
            next();
            while (std::isdigit(peek()))
            {
                next();
            }
        }

        if (peek() == 'e' || peek() == 'E')
        {
            next();
            if (peek() == '+' || peek() == '-')
            {
                next();
            }
            while (std::isdigit(peek()))
            {
                next();
            }
        }

        std::string numStr = json_.substr(start, pos_ - start);
        return JsonValue(std::stod(numStr));
    }

    JsonValue parseString()
    {
        if (next() != '"')
        {
            throw std::runtime_error("Expected '\"'");
        }

        std::string result;
        while (peek() != '"')
        {
            char c = next();
            if (c == '\\')
            {
                char escaped = next();
                switch (escaped)
                {
                    case '"':
                        result += '"';
                        break;
                    case '\\':
                        result += '\\';
                        break;
                    case '/':
                        result += '/';
                        break;
                    case 'b':
                        result += '\b';
                        break;
                    case 'f':
                        result += '\f';
                        break;
                    case 'n':
                        result += '\n';
                        break;
                    case 'r':
                        result += '\r';
                        break;
                    case 't':
                        result += '\t';
                        break;
                    default:
                        result += escaped;
                }
            }
            else
            {
                result += c;
            }
        }
        next();  // consume closing '"'

        return JsonValue(result);
    }

    JsonValue parseArray()
    {
        if (next() != '[')
        {
            throw std::runtime_error("Expected '['");
        }

        JsonValue arr;
        arr.setArray();

        skipWhitespace();
        if (peek() == ']')
        {
            next();
            return arr;
        }

        while (true)
        {
            arr.append(parseValue());
            skipWhitespace();

            if (peek() == ']')
            {
                next();
                break;
            }

            if (next() != ',')
            {
                throw std::runtime_error("Expected ',' or ']'");
            }
        }

        return arr;
    }

    JsonValue parseObject()
    {
        if (next() != '{')
        {
            throw std::runtime_error("Expected '{'");
        }

        JsonValue obj;
        obj.setObject();

        skipWhitespace();
        if (peek() == '}')
        {
            next();
            return obj;
        }

        while (true)
        {
            skipWhitespace();
            JsonValue key = parseString();
            skipWhitespace();

            if (next() != ':')
            {
                throw std::runtime_error("Expected ':'");
            }

            JsonValue value = parseValue();
            obj.set(key.asString(), value);

            skipWhitespace();
            if (peek() == '}')
            {
                next();
                break;
            }

            if (next() != ',')
            {
                throw std::runtime_error("Expected ',' or '}'");
            }
        }

        return obj;
    }
};

JsonValue JsonValue::parse(const std::string& json)
{
    JsonParser parser(json);
    return parser.parse();
}

}  // namespace jose
}  // namespace Vlinder
