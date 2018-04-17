Unit tests (C++, gtest) under here.

Headers from under this portableUnitTests directory may be #included
by tests in dependent projects, and a library of shared test data
may be linked to (eg weather tapes and the equivalent).

Shared routines may also be linked to, but the difficulties of ensuring
exactly matching test library support (eg gtest) may make this fragile.
Header-based inline/template routine may be preferable.

This may be transiently true "all the way down" for OpenTRV libraries.