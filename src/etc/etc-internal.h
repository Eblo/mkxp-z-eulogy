/*
** etc-internal.h
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

#ifndef ETC_TYPES_H
#define ETC_TYPES_H

#include "util.h"
#include "serial-util.h"
#include "util/exception.h"

#include <SDL_rect.h>

struct Vec2
{
	float x, y;

	Vec2()
	    : x(0), y(0)
	{}

	Vec2(float x, float y)
	    : x(x), y(y)
	{}

	bool operator==(const Vec2 &other) const
	{
		return (x == other.x && y == other.y);
	}
	
	float getX() const { return x; }
	float getY() const { return y; }

	void setX(float x) { this->x = x; }
	void setY(float y) { this->y = y; }

	void set(float x, float y)
	{
		this->x = x;
		this->y = y;
	}

	int serialSize() {
		return 4 * 4;
	}

	void serialize(char *buffer)
	{
		writeDouble(&buffer, x);
		writeDouble(&buffer, y);
	}

	static Vec2* deserialize(const char *data, int len)
	{
		if (len != 16) throw Exception(Exception::ArgumentError, "Vec2: Serialized data invalid");

		Vec2* vec2 = new Vec2();
		vec2->x = readDouble(&data);
		vec2->y = readDouble(&data);

		return vec2;
	}
};

struct Vec4
{
	float x, y, z, w;

	Vec4()
	    : x(0), y(0), z(0), w(0)
	{}

	Vec4(float x, float y, float z, float w)
	    : x(x), y(y), z(z), w(w)
	{}

	bool operator==(const Vec4 &other) const
	{
		return (x == other.x && y == other.y && z == other.z && w == other.w);
	}

	bool xyzNotNull() const
	{
		return (x != 0.0f || y != 0.0f || z != 0.0f);
	}

	float getX() const { return x; }
	float getY() const { return y; }
	float getZ() const { return z; }	
	float getW() const { return w; }

	void setX(float x) { this->x = x; }
	void setY(float y) { this->y = y; }
	void setZ(float z) { this->z = z; }
	void setW(float w) { this->w = w; }

	void set(float x, float y, float z, float w)
	{
		this->x = x;
		this->y = y;
		this->z = z;
		this->w = w;
	}

	int serialSize() {
		return 4 * 8;
	}

	void serialize(char *buffer)
	{
		writeDouble(&buffer, x);
		writeDouble(&buffer, y);
		writeDouble(&buffer, z);
		writeDouble(&buffer, w);
	}

	static Vec4* deserialize(const char *data, int len)
	{
		if (len != 32) throw Exception(Exception::ArgumentError, "Vec4: Serialized data invalid");

		Vec4* vec4 = new Vec4();
		vec4->x = readDouble(&data);
		vec4->y = readDouble(&data);
		vec4->z = readDouble(&data);
		vec4->w = readDouble(&data);

		return vec4;
	}
};

struct Vec2i
{
	int x, y;

	Vec2i()
	    : x(0), y(0)
	{}

	Vec2i(int x, int y)
	    : x(x), y(y)
	{}

	explicit Vec2i(int xy)
	    : x(xy), y(xy)
	{}

	bool operator==(const Vec2i &other) const
	{
		return x == other.x && y == other.y;
	}

	bool operator!=(const Vec2i &other) const
	{
		return !(*this == other);
	}

	Vec2i &operator+=(const Vec2i &value)
	{
		x += value.x;
		y += value.y;

		return *this;
	}

	Vec2i &operator-=(const Vec2i &value)
	{
		x -= value.x;
		y -= value.y;

		return *this;
	}

	Vec2i operator+(const Vec2i &value) const
	{
		return Vec2i(x + value.x, y + value.y);
	}

	Vec2i operator-(const Vec2i &value) const
	{
		return Vec2i(x - value.x, y - value.y);
	}

	template<typename T>
	Vec2i operator*(T value) const
	{
		return Vec2i(x * value, y * value);
	}

	template<typename T>
	Vec2i operator/(T value) const
	{
		return Vec2i(x / value, y / value);
	}

	Vec2i operator%(int value) const
	{
		return Vec2i(x % value, y % value);
	}

	Vec2i operator&(unsigned value) const
	{
		return Vec2i(x & value, y & value);
	}

	Vec2i operator-() const
	{
		return Vec2i(-x, -y);
	}

	Vec2i operator!() const
	{
		return Vec2i(!x, !y);
	}

	operator Vec2() const
	{
		return Vec2(x, y);
	}

	int getX() const { return x; }
	int getY() const { return y; }

	void setX(int x) { this->x = x; }
	void setY(int y) { this->y = y; }

	void set(int x, int y)
	{
		this->x = x;
		this->y = y;
	}
};

struct IntRect : SDL_Rect
{
	IntRect()
	{
		x = y = w = h = 0;
	}

	IntRect(int x, int y, int w, int h)
	{
		this->x = x;
		this->y = y;
		this->w = w;
		this->h = h;
	}

	IntRect(const Vec2i &pos, const Vec2i &size)
	{
		x = pos.x;
		y = pos.y;
		w = size.x;
		h = size.y;
	}

	bool operator==(const IntRect &other) const
	{
		return (x == other.x && y == other.y &&
		        w == other.w && h == other.h);
	}

	bool operator!=(const IntRect &other) const
	{
		return !(*this == other);
	}

	Vec2i pos() const
	{
		return Vec2i(x, y);
	}

	Vec2i size() const
	{
		return Vec2i(w, h);
	}

	void setPos(const Vec2i &value)
	{
		x = value.x;
		y = value.y;
	}

	void setSize(const Vec2i &value)
	{
		w = value.x;
		h = value.y;
	}

	bool encloses(const IntRect &o) const
	{
		return (x   <= o.x &&
		        y   <= o.y &&
		        x+w >= o.x+o.w &&
		        y+h >= o.y+o.h);
	}
};

struct StaticRect { float x, y, w, h; };

struct FloatRect
{
	float x, y, w, h;

	FloatRect()
	    : x(0), y(0), w(0), h(0)
	{}

	FloatRect(float x, float y, float w, float h)
	    : x(x), y(y), w(w), h(h)
	{}

	FloatRect(const StaticRect &d)
	    : x(d.x), y(d.y), w(d.w), h(d.h)
	{}

	FloatRect(const IntRect &r)
	    : x(r.x), y(r.y), w(r.w), h(r.h)
	{}

	operator IntRect() const
	{
		return IntRect(x, y, w, h);
	}

	Vec2 topLeft() const { return Vec2(x, y); }
	Vec2 bottomLeft() const { return Vec2(x, y+h); }
	Vec2 topRight() const { return Vec2(x+w, y); }
	Vec2 bottomRight() const { return Vec2(x+w, y+h); }

	FloatRect hFlipped() const
	{
		return FloatRect(x+w, y, -w, h);
	}

	FloatRect vFlipped() const
	{
		return FloatRect(x, y+h, w, -h);
	}
};

/* Value between 0 and 255 with internal
 * normalized representation */
struct NormValue
{
	int unNorm;
	float norm;

	NormValue()
	    : unNorm(0),
	      norm(0)
	{}

	NormValue(int unNorm)
	    : unNorm(unNorm),
	      norm(unNorm / 255.0f)
	{}

	void operator =(int value)
	{
		unNorm = clamp(value, 0, 255);
		norm = unNorm / 255.0f;
	}

	bool operator ==(int value) const
	{
		return unNorm == clamp(value, 0, 255);
	}

	operator int() const
	{
		return unNorm;
	}
};

#endif // ETC_TYPES_H
