/*
** serializable-binding.h
**
** This file is part of mkxp.
**
** Copyright (C) 2013 - 2021 Amaryllis Kulla <ancurio@mapleshrine.eu>
**
** mkxp is free software: you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation, either version 2 of the License, or
** (at your option) any later version.
**
** mkxp is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with mkxp.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SERIALIZABLEBINDING_H
#define SERIALIZABLEBINDING_H

#include "serializable.h"
#include "binding-util.h"
#include "exception.h"

template<class C>
static VALUE
serializableDump(int, VALUE *, VALUE self)
{
	// In practice, this is always a Serializable except for Vec2 and Vec4. I had compilation issues trying to make
	// those structs extend Serializable, so I'm making this concession for convenience.
	C *s = getPrivateData<C>(self);

	int dataSize = s->serialSize();

	VALUE data = rb_str_new(0, dataSize);

	Exception *exc = 0;
	try{
		s->serialize(RSTRING_PTR(data));
	} catch (const Exception &e) {
		exc = new Exception(e);
	}

	if (exc) {
		raiseRbExc(exc);
	}

	return data;
}

template<class C>
void
serializableBindingInit(VALUE klass)
{
	_rb_define_method(klass, "_dump", serializableDump<C>);
}

#endif // SERIALIZABLEBINDING_H
