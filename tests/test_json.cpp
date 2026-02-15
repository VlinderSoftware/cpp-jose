#include <gtest/gtest.h>

#include <string>

#include "jose/jose.hpp"

using namespace Vlinder::JOSE;

class JsonValueTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
    }
    void TearDown() override
    {
    }
};

// Constructor tests
TEST_F(JsonValueTest, DefaultConstructor)
{
    JsonValue value;
    EXPECT_TRUE(value.isNull());
    EXPECT_EQ(JsonValue::Type::Null, value.getType());
}

TEST_F(JsonValueTest, BooleanConstructor)
{
    JsonValue true_value(true);
    EXPECT_TRUE(true_value.isBoolean());
    EXPECT_EQ(JsonValue::Type::Boolean, true_value.getType());
    EXPECT_TRUE(true_value.asBoolean());

    JsonValue false_value(false);
    EXPECT_TRUE(false_value.isBoolean());
    EXPECT_FALSE(false_value.asBoolean());
}

TEST_F(JsonValueTest, IntegerConstructor)
{
    JsonValue value(42);
    EXPECT_TRUE(value.isNumber());
    EXPECT_EQ(JsonValue::Type::Number, value.getType());
    EXPECT_DOUBLE_EQ(42.0, value.asNumber());
}

TEST_F(JsonValueTest, DoubleConstructor)
{
    JsonValue value(3.14159);
    EXPECT_TRUE(value.isNumber());
    EXPECT_DOUBLE_EQ(3.14159, value.asNumber());
}

TEST_F(JsonValueTest, StringConstructor)
{
    JsonValue value("hello world");
    EXPECT_TRUE(value.isString());
    EXPECT_EQ(JsonValue::Type::String, value.getType());
    EXPECT_EQ("hello world", value.asString());
}

TEST_F(JsonValueTest, StringConstructorFromStdString)
{
    std::string str = "test string";
    JsonValue value(str);
    EXPECT_TRUE(value.isString());
    EXPECT_EQ("test string", value.asString());
}

// Type checking
TEST_F(JsonValueTest, TypeChecking)
{
    JsonValue null_value;
    EXPECT_TRUE(null_value.isNull());
    EXPECT_FALSE(null_value.isBoolean());
    EXPECT_FALSE(null_value.isNumber());
    EXPECT_FALSE(null_value.isString());
    EXPECT_FALSE(null_value.isArray());
    EXPECT_FALSE(null_value.isObject());

    JsonValue bool_value(true);
    EXPECT_FALSE(bool_value.isNull());
    EXPECT_TRUE(bool_value.isBoolean());
    EXPECT_FALSE(bool_value.isNumber());

    JsonValue num_value(42);
    EXPECT_FALSE(num_value.isNull());
    EXPECT_FALSE(num_value.isBoolean());
    EXPECT_TRUE(num_value.isNumber());

    JsonValue str_value("test");
    EXPECT_FALSE(str_value.isNull());
    EXPECT_TRUE(str_value.isString());
}

// Array operations
TEST_F(JsonValueTest, CreateArray)
{
    JsonValue arr;
    arr.setArray();
    EXPECT_TRUE(arr.isArray());
    EXPECT_EQ(JsonValue::Type::Array, arr.getType());
}

TEST_F(JsonValueTest, AppendToArray)
{
    JsonValue arr;
    arr.setArray();
    arr.append(JsonValue(1));
    arr.append(JsonValue(2));
    arr.append(JsonValue("three"));

    EXPECT_TRUE(arr[0].isNumber());
    EXPECT_DOUBLE_EQ(1.0, arr[0].asNumber());
    EXPECT_DOUBLE_EQ(2.0, arr[1].asNumber());
    EXPECT_EQ("three", arr[2].asString());
}

TEST_F(JsonValueTest, ArrayIndexing)
{
    JsonValue arr;
    arr.setArray();
    arr.append(JsonValue(10));
    arr.append(JsonValue(20));
    arr.append(JsonValue(30));

    EXPECT_DOUBLE_EQ(10.0, arr[0].asNumber());
    EXPECT_DOUBLE_EQ(20.0, arr[1].asNumber());
    EXPECT_DOUBLE_EQ(30.0, arr[2].asNumber());
}

TEST_F(JsonValueTest, MixedTypeArray)
{
    JsonValue arr;
    arr.setArray();
    arr.append(JsonValue(42));
    arr.append(JsonValue("text"));
    arr.append(JsonValue(true));
    arr.append(JsonValue(3.14));

    EXPECT_TRUE(arr[0].isNumber());
    EXPECT_TRUE(arr[1].isString());
    EXPECT_TRUE(arr[2].isBoolean());
    EXPECT_TRUE(arr[3].isNumber());
}

// Object operations
TEST_F(JsonValueTest, CreateObject)
{
    JsonValue obj;
    obj.setObject();
    EXPECT_TRUE(obj.isObject());
    EXPECT_EQ(JsonValue::Type::Object, obj.getType());
}

TEST_F(JsonValueTest, SetObjectProperties)
{
    JsonValue obj;
    obj.setObject();
    obj.set("name", JsonValue("John"));
    obj.set("age", JsonValue(30));
    obj.set("active", JsonValue(true));

    EXPECT_EQ("John", obj["name"].asString());
    EXPECT_DOUBLE_EQ(30.0, obj["age"].asNumber());
    EXPECT_TRUE(obj["active"].asBoolean());
}

TEST_F(JsonValueTest, ObjectHasKey)
{
    JsonValue obj;
    obj.setObject();
    obj.set("key1", JsonValue("value1"));
    obj.set("key2", JsonValue(123));

    EXPECT_TRUE(obj.has("key1"));
    EXPECT_TRUE(obj.has("key2"));
    EXPECT_FALSE(obj.has("key3"));
    EXPECT_FALSE(obj.has("nonexistent"));
}

TEST_F(JsonValueTest, ObjectPropertyAccess)
{
    JsonValue obj;
    obj.setObject();
    obj.set("message", JsonValue("Hello World"));
    obj.set("count", JsonValue(99));

    EXPECT_EQ("Hello World", obj["message"].asString());
    EXPECT_DOUBLE_EQ(99.0, obj["count"].asNumber());
}

// Nested structures
TEST_F(JsonValueTest, NestedArray)
{
    JsonValue outer;
    outer.setArray();

    JsonValue inner;
    inner.setArray();
    inner.append(JsonValue(1));
    inner.append(JsonValue(2));

    outer.append(inner);
    outer.append(JsonValue("test"));

    EXPECT_TRUE(outer[0].isArray());
    EXPECT_DOUBLE_EQ(1.0, outer[0][0].asNumber());
    EXPECT_DOUBLE_EQ(2.0, outer[0][1].asNumber());
    EXPECT_EQ("test", outer[1].asString());
}

TEST_F(JsonValueTest, NestedObject)
{
    JsonValue outer;
    outer.setObject();

    JsonValue inner;
    inner.setObject();
    inner.set("x", JsonValue(10));
    inner.set("y", JsonValue(20));

    outer.set("point", inner);
    outer.set("name", JsonValue("origin"));

    EXPECT_TRUE(outer["point"].isObject());
    EXPECT_DOUBLE_EQ(10.0, outer["point"]["x"].asNumber());
    EXPECT_DOUBLE_EQ(20.0, outer["point"]["y"].asNumber());
}

TEST_F(JsonValueTest, ObjectWithArray)
{
    JsonValue obj;
    obj.setObject();

    JsonValue arr;
    arr.setArray();
    arr.append(JsonValue(1));
    arr.append(JsonValue(2));
    arr.append(JsonValue(3));

    obj.set("numbers", arr);
    obj.set("description", JsonValue("test"));

    EXPECT_TRUE(obj["numbers"].isArray());
    EXPECT_DOUBLE_EQ(2.0, obj["numbers"][1].asNumber());
}

TEST_F(JsonValueTest, ArrayOfObjects)
{
    JsonValue arr;
    arr.setArray();

    JsonValue obj1;
    obj1.setObject();
    obj1.set("id", JsonValue(1));
    obj1.set("name", JsonValue("Alice"));

    JsonValue obj2;
    obj2.setObject();
    obj2.set("id", JsonValue(2));
    obj2.set("name", JsonValue("Bob"));

    arr.append(obj1);
    arr.append(obj2);

    EXPECT_EQ("Alice", arr[0]["name"].asString());
    EXPECT_EQ("Bob", arr[1]["name"].asString());
}

// Serialization tests
TEST_F(JsonValueTest, SerializeNull)
{
    JsonValue value;
    std::string json = value.serialize();
    EXPECT_EQ("null", json);
}

TEST_F(JsonValueTest, SerializeBoolean)
{
    JsonValue true_val(true);
    EXPECT_EQ("true", true_val.serialize());

    JsonValue false_val(false);
    EXPECT_EQ("false", false_val.serialize());
}

TEST_F(JsonValueTest, SerializeNumber)
{
    JsonValue int_val(42);
    std::string json = int_val.serialize();
    EXPECT_NE(std::string::npos, json.find("42"));

    JsonValue double_val(3.14);
    json = double_val.serialize();
    EXPECT_NE(std::string::npos, json.find("3.14"));
}

TEST_F(JsonValueTest, SerializeString)
{
    JsonValue value("hello");
    std::string json = value.serialize();
    EXPECT_EQ("\"hello\"", json);
}

TEST_F(JsonValueTest, SerializeStringWithEscapes)
{
    JsonValue value("hello \"world\"");
    std::string json = value.serialize();
    // Should contain escaped quotes
    EXPECT_NE(std::string::npos, json.find("\\\""));
}

TEST_F(JsonValueTest, SerializeArray)
{
    JsonValue arr;
    arr.setArray();
    arr.append(JsonValue(1));
    arr.append(JsonValue(2));
    arr.append(JsonValue(3));

    std::string json = arr.serialize();
    EXPECT_NE(std::string::npos, json.find("["));
    EXPECT_NE(std::string::npos, json.find("]"));
    EXPECT_NE(std::string::npos, json.find("1"));
    EXPECT_NE(std::string::npos, json.find("2"));
    EXPECT_NE(std::string::npos, json.find("3"));
}

TEST_F(JsonValueTest, SerializeObject)
{
    JsonValue obj;
    obj.setObject();
    obj.set("name", JsonValue("test"));
    obj.set("value", JsonValue(123));

    std::string json = obj.serialize();
    EXPECT_NE(std::string::npos, json.find("{"));
    EXPECT_NE(std::string::npos, json.find("}"));
    EXPECT_NE(std::string::npos, json.find("name"));
    EXPECT_NE(std::string::npos, json.find("test"));
    EXPECT_NE(std::string::npos, json.find("value"));
    EXPECT_NE(std::string::npos, json.find("123"));
}

// Parsing tests
TEST_F(JsonValueTest, ParseNull)
{
    JsonValue value = JsonValue::parse("null");
    EXPECT_TRUE(value.isNull());
}

TEST_F(JsonValueTest, ParseBoolean)
{
    JsonValue true_val = JsonValue::parse("true");
    EXPECT_TRUE(true_val.isBoolean());
    EXPECT_TRUE(true_val.asBoolean());

    JsonValue false_val = JsonValue::parse("false");
    EXPECT_TRUE(false_val.isBoolean());
    EXPECT_FALSE(false_val.asBoolean());
}

TEST_F(JsonValueTest, ParseNumber)
{
    JsonValue int_val = JsonValue::parse("42");
    EXPECT_TRUE(int_val.isNumber());
    EXPECT_DOUBLE_EQ(42.0, int_val.asNumber());

    JsonValue double_val = JsonValue::parse("3.14159");
    EXPECT_TRUE(double_val.isNumber());
    EXPECT_NEAR(3.14159, double_val.asNumber(), 0.00001);
}

TEST_F(JsonValueTest, ParseString)
{
    JsonValue value = JsonValue::parse("\"hello world\"");
    EXPECT_TRUE(value.isString());
    EXPECT_EQ("hello world", value.asString());
}

TEST_F(JsonValueTest, ParseArray)
{
    JsonValue arr = JsonValue::parse("[1, 2, 3]");
    EXPECT_TRUE(arr.isArray());
    EXPECT_DOUBLE_EQ(1.0, arr[0].asNumber());
    EXPECT_DOUBLE_EQ(2.0, arr[1].asNumber());
    EXPECT_DOUBLE_EQ(3.0, arr[2].asNumber());
}

TEST_F(JsonValueTest, ParseObject)
{
    JsonValue obj = JsonValue::parse("{\"name\":\"test\",\"value\":123}");
    EXPECT_TRUE(obj.isObject());
    EXPECT_EQ("test", obj["name"].asString());
    EXPECT_DOUBLE_EQ(123.0, obj["value"].asNumber());
}

TEST_F(JsonValueTest, ParseNestedStructure)
{
    std::string json = R"(
        {
            "user": {
                "name": "Alice",
                "age": 30,
                "active": true
            },
            "scores": [95, 87, 92]
        }
    )";

    JsonValue obj = JsonValue::parse(json);
    EXPECT_TRUE(obj.isObject());
    EXPECT_TRUE(obj["user"].isObject());
    EXPECT_EQ("Alice", obj["user"]["name"].asString());
    EXPECT_DOUBLE_EQ(30.0, obj["user"]["age"].asNumber());
    EXPECT_TRUE(obj["user"]["active"].asBoolean());
    EXPECT_TRUE(obj["scores"].isArray());
    EXPECT_DOUBLE_EQ(95.0, obj["scores"][0].asNumber());
}

// Round-trip tests
TEST_F(JsonValueTest, RoundTripSimpleObject)
{
    JsonValue original;
    original.setObject();
    original.set("key", JsonValue("value"));

    std::string json = original.serialize();
    JsonValue parsed = JsonValue::parse(json);

    EXPECT_TRUE(parsed.isObject());
    EXPECT_EQ("value", parsed["key"].asString());
}

TEST_F(JsonValueTest, RoundTripComplexStructure)
{
    JsonValue original;
    original.setObject();
    original.set("string", JsonValue("text"));
    original.set("number", JsonValue(42));
    original.set("boolean", JsonValue(true));

    JsonValue arr;
    arr.setArray();
    arr.append(JsonValue(1));
    arr.append(JsonValue(2));
    original.set("array", arr);

    std::string json = original.serialize();
    JsonValue parsed = JsonValue::parse(json);

    EXPECT_EQ("text", parsed["string"].asString());
    EXPECT_DOUBLE_EQ(42.0, parsed["number"].asNumber());
    EXPECT_TRUE(parsed["boolean"].asBoolean());
    EXPECT_DOUBLE_EQ(1.0, parsed["array"][0].asNumber());
}

// Edge cases
TEST_F(JsonValueTest, EmptyString)
{
    JsonValue value("");
    EXPECT_TRUE(value.isString());
    EXPECT_EQ("", value.asString());
}

TEST_F(JsonValueTest, EmptyArray)
{
    JsonValue arr;
    arr.setArray();
    std::string json = arr.serialize();
    JsonValue parsed = JsonValue::parse(json);
    EXPECT_TRUE(parsed.isArray());
}

TEST_F(JsonValueTest, EmptyObject)
{
    JsonValue obj;
    obj.setObject();
    std::string json = obj.serialize();
    JsonValue parsed = JsonValue::parse(json);
    EXPECT_TRUE(parsed.isObject());
}

TEST_F(JsonValueTest, SpecialCharactersInString)
{
    JsonValue value("Line1\nLine2\tTabbed");
    std::string json = value.serialize();
    JsonValue parsed = JsonValue::parse(json);
    EXPECT_EQ("Line1\nLine2\tTabbed", parsed.asString());
}
