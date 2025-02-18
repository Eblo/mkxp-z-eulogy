/*
** audio-binding.cpp
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

#include "audio.h"
#include "sharedstate.h"
#include "binding-util.h"
#include "exception.h"

#define DEF_PLAY_STOP_POS(entity) \
	RB_METHOD_GUARD(audio_##entity##Play) \
	{ \
		RB_UNUSED_PARAM; \
		const char *filename; \
		int volume = 100; \
		int pitch = 100; \
		double pos = 0.0; \
		rb_get_args(argc, argv, "z|iif", &filename, &volume, &pitch, &pos RB_ARG_END); \
		shState->audio().entity##Play(filename, volume, pitch, pos); \
		return Qnil; \
	} \
	RB_METHOD_GUARD_END \
	RB_METHOD(audio_##entity##Stop) \
	{ \
		RB_UNUSED_PARAM; \
		shState->audio().entity##Stop(); \
		return Qnil; \
	} \
	RB_METHOD(audio_##entity##Pos) \
	{ \
		RB_UNUSED_PARAM; \
		return rb_float_new(shState->audio().entity##Pos()); \
	}

#define DEF_PLAY_STOP(entity) \
	RB_METHOD_GUARD(audio_##entity##Play) \
	{ \
		RB_UNUSED_PARAM; \
		const char *filename; \
		int volume = 100; \
		int pitch = 100; \
		rb_get_args(argc, argv, "z|ii", &filename, &volume, &pitch RB_ARG_END); \
		shState->audio().entity##Play(filename, volume, pitch); \
		return Qnil; \
	} \
	RB_METHOD_GUARD_END \
	RB_METHOD(audio_##entity##Stop) \
	{ \
		RB_UNUSED_PARAM; \
		shState->audio().entity##Stop(); \
		return Qnil; \
	}

#define DEF_FADE(entity) \
RB_METHOD(audio_##entity##Fade) \
{ \
	RB_UNUSED_PARAM; \
	int time; \
	rb_get_args(argc, argv, "i", &time RB_ARG_END); \
	shState->audio().entity##Fade(time); \
	return Qnil; \
}

#define DEF_POS(entity) \
	RB_METHOD(audio_##entity##Pos) \
	{ \
		RB_UNUSED_PARAM; \
		return rb_float_new(shState->audio().entity##Pos()); \
	}

// DEF_PLAY_STOP_POS( bgm )

#define MAYBE_NIL_TRACK(t) t == Qnil ? -127 : NUM2INT(t)

RB_METHOD_GUARD(audio_bgmPlay)
{
    RB_UNUSED_PARAM;
    const char *filename;
    int volume = 100;
    int pitch = 100;
    double pos = 0.0;
	bool fadein = true;
    VALUE track = Qnil;
    rb_get_args(argc, argv, "z|iifbo", &filename, &volume, &pitch, &pos, &fadein, &track RB_ARG_END);
    shState->audio().bgmPlay(filename, volume, pitch, pos, fadein, MAYBE_NIL_TRACK(track));
    return Qnil;
}
RB_METHOD_GUARD_END

RB_METHOD(audio_bgmStop)
{
    RB_UNUSED_PARAM;
    VALUE track = Qnil;
    rb_get_args(argc, argv, "|o", &track RB_ARG_END);
    shState->audio().bgmStop(MAYBE_NIL_TRACK(track));
    return Qnil;
}

RB_METHOD(audio_bgmPos)
{
    RB_UNUSED_PARAM;
    VALUE track = Qnil;
    rb_get_args(argc, argv, "|o", &track RB_ARG_END);
    return rb_float_new(shState->audio().bgmPos(MAYBE_NIL_TRACK(track)));
}

RB_METHOD_GUARD(audio_bgmGetVolume)
{
    RB_UNUSED_PARAM;
    VALUE track = Qnil;
    rb_get_args(argc, argv, "|o", &track RB_ARG_END);
    int ret = 0;
    ret = shState->audio().bgmGetVolume(MAYBE_NIL_TRACK(track));
    return rb_fix_new(ret);
}
RB_METHOD_GUARD_END

RB_METHOD_GUARD(audio_bgmSetVolume)
{
    RB_UNUSED_PARAM;
    int volume;
    VALUE track = Qnil;
    rb_get_args(argc, argv, "i|o", &volume, &track RB_ARG_END);
    shState->audio().bgmSetVolume(volume, MAYBE_NIL_TRACK(track));
    return Qnil;
}
RB_METHOD_GUARD_END

RB_METHOD(audio_bgmSetLoopPoints)
{
    RB_UNUSED_PARAM;
    int newLoopStart, newLoopLength;
    VALUE track = Qnil;
    rb_get_args(argc, argv, "ii|o", &newLoopStart, &newLoopLength, &track RB_ARG_END);
    shState->audio().bgmSetLoopPoints(newLoopStart, newLoopLength, MAYBE_NIL_TRACK(track));
    return Qnil;
}

RB_METHOD(audio_bgmGetComments)
{
    RB_UNUSED_PARAM;
    VALUE track = Qnil;
    rb_get_args(argc, argv, "o", &track RB_ARG_END);
	int numComments = 0;
	char** sourceComments;
    VALUE comments = rb_ary_new();
	numComments = shState->audio().bgmGetNumberOfComments(MAYBE_NIL_TRACK(track));
	sourceComments = shState->audio().bgmGetComments(MAYBE_NIL_TRACK(track));
	for(int i = 0; i < numComments; i++) {
		rb_ary_push(comments, rb_str_new_cstr(sourceComments[i]));
	}
    return comments;
}

DEF_PLAY_STOP_POS( bgs )

DEF_PLAY_STOP( me )

//DEF_FADE( bgm )
RB_METHOD(audio_bgmFade)
{
    RB_UNUSED_PARAM;
    int time;
    VALUE track = Qnil;
    rb_get_args(argc, argv, "i|o", &time, &track RB_ARG_END);
    shState->audio().bgmFade(time, MAYBE_NIL_TRACK(track));
    return Qnil;
}

DEF_FADE( bgs )
DEF_FADE( me )

DEF_PLAY_STOP( se )

RB_METHOD(audioReset)
{
	RB_UNUSED_PARAM;

	shState->audio().reset();

	return Qnil;
}


#define BIND_PLAY_STOP(entity) \
	_rb_define_module_function(module, #entity "_play", audio_##entity##Play); \
	_rb_define_module_function(module, #entity "_stop", audio_##entity##Stop);

#define BIND_FADE(entity) \
	_rb_define_module_function(module, #entity "_fade", audio_##entity##Fade);

#define BIND_PLAY_STOP_FADE(entity) \
	BIND_PLAY_STOP(entity) \
	BIND_FADE(entity)

#define BIND_POS(entity) \
	_rb_define_module_function(module, #entity "_pos", audio_##entity##Pos);


void
audioBindingInit()
{
	VALUE module = rb_define_module("Audio");

	BIND_PLAY_STOP_FADE( bgm );
    _rb_define_module_function(module, "bgm_volume", audio_bgmGetVolume);
    _rb_define_module_function(module, "bgm_set_volume", audio_bgmSetVolume);
    _rb_define_module_function(module, "bgm_set_loop_points", audio_bgmSetLoopPoints);
    _rb_define_module_function(module, "bgm_comments", audio_bgmGetComments);
	BIND_PLAY_STOP_FADE( bgs );
	BIND_PLAY_STOP_FADE( me  );

	BIND_POS( bgm );
	BIND_POS( bgs );

	BIND_PLAY_STOP( se )

	_rb_define_module_function(module, "__reset__", audioReset);
}
