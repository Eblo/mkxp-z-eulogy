/*
** rgssad.h
**
** This file is part of mkxp.
**
** Copyright (C) 2014 - 2021 Amaryllis Kulla <ancurio@mapleshrine.eu>
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

#ifndef RGSSAD_H
#define RGSSAD_H

#include <string>
#include <physfs.h>

extern const PHYSFS_Archiver Bugs_Archiver;

void BUGS_openMetaArchive(PHYSFS_Io *io, std::string password, int keyMultiplier, int keyAdditive);

#endif // RGSSAD_H
