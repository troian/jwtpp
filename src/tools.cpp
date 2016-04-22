//
// Created by Artur Troian on 4/21/16.
//

#include <tools/tools.hpp>

std::string serialize_json(const Json::Value &json)
{
	Json::StreamWriterBuilder wbuilder;

	std::string s = Json::writeString(wbuilder, json);

	return s;
}
