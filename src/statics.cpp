//
// Created by Artur Troian on 16.10.2019
//

#include <jwtpp/statics.hh>

namespace jwtpp {

//#if defined(__GNUC__)
//__attribute__((used))
//#endif
//static_init *instance = instantiate<static_init>();

static_init &static_instance = static_init::inst();

} // namespace jwtpp
