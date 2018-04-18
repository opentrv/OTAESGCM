#!/bin/sh

# *************************************************************
#
# The OpenTRV project licenses this file to you
# under the Apache Licence, Version 2.0 (the "Licence");
# you may not use this file except in compliance
# with the Licence. You may obtain a copy of the Licence at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the Licence is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the Licence for the
# specific language governing permissions and limitations
# under the Licence.
#
# *************************************************************
# Author(s) / Copyright (s): Damon Hart-Davis 2016--2017
#                            Deniz Erbilgin 2017
#                            Mark Hill 2017


# Script to be able to run on common Linux and *nix-like OSes (eg macOS)
# to build and run the C++ unit tests under the portableUnitTests directory.
#
# Requires a newish g++ (even if a front-end to Clang for example)
# and with gtest includes and libraries in system paths or under
# /usr/local/{lib,include}.
#
# The COMPILER environment variable can be used to specify
# a different compiler, eg g++-4.9.
#
# Intended to be run without arguments from top-level dir of project.
#
# Run as:
#
#     sh ./portableUnitTestsDriver.sh

# Generates a temporary executable at top level.
EXENAME=tmptestexe

# Project source root.
PROJSRCROOT=content/OTAESGCM
# Project source files under test.
PROJSRCS="`find ${PROJSRCROOT} -name '*.cpp' -type f -print`"

# Test source files dir.
TESTSRCDIR=portableUnitTests
# Source files.
TESTSRCS="`find ${TESTSRCDIR} -name '*.cpp' -type f -print`"

# GTest libs (including main()).
GLIBS="-lgtest -lgtest_main -lpthread"
# Other libs.
OTHERLIBS=

# GTest libs (paths).
GLIBDIRS="-L/usr/local/lib"

# Glib includes (paths).
GINCLUDES="-I/usr/local/include"
# Source includes (paths).
INCLUDES="-I${PROJSRCROOT} -I${PROJSRCROOT}/utility -IportableUnitTests"

#echo "Using test sources: $TESTSRCS"
#echo "Using project sources: $PROJSRCS"

rm -f ${EXENAME}
if ${COMPILER:-g++} -o ${EXENAME} -std=c++0x -O0 -Wall -Werror -fstack-check -fstack-protector-strong ${INCLUDES} ${GINCLUDES} ${PROJSRCS} ${TESTSRCS} ${GLIBDIRS} ${GLIBS} ${OTHERLIBS} ; then
    echo Compiled.
else
    echo Failed to compile.
    exit 2
fi

# Run the tests, repeatedly, shuffled (except first run to make diffs easier).
# Run in increasingly large blocks
./${EXENAME} --gtest_repeat=1 \
  && ./${EXENAME} --gtest_shuffle --gtest_repeat=10 \
  && ./${EXENAME} --gtest_shuffle --gtest_repeat=100 \
  && echo OK
