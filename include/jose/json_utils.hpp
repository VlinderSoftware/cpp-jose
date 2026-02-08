#ifndef JOSE_JSON_UTILS_HPP
#define JOSE_JSON_UTILS_HPP

#include <string>
#include <map>
#include <vector>
#include <memory>

namespace Vlinder
{
namespace jose
{

/**
 * @brief Simple JSON value representation
 */
class JsonValue
{
public:
    enum class Type
    {
        Null,
        Boolean,
        Number,
        String,
        Array,
        Object
    };
    
    JsonValue();
    explicit JsonValue(bool value);
    explicit JsonValue(int value);
    explicit JsonValue(double value);
    explicit JsonValue(const std::string& value);
    explicit JsonValue(const char* value);
    
    Type getType() const;
    
    bool isNull() const;
    bool isBoolean() const;
    bool isNumber() const;
    bool isString() const;
    bool isArray() const;
    bool isObject() const;
    
    bool asBoolean() const;
    double asNumber() const;
    std::string asString() const;
    
    void setArray();
    void setObject();
    
    void append(const JsonValue& value);
    void set(const std::string& key, const JsonValue& value);
    
    const JsonValue& operator[](size_t index) const;
    const JsonValue& operator[](const std::string& key) const;
    
    bool has(const std::string& key) const;
    
    std::string serialize() const;
    static JsonValue parse(const std::string& json);
    
private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

} // namespace jose
} // namespace Vlinder

#endif // JOSE_JSON_UTILS_HPP
