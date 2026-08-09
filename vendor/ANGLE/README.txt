Here lives Google's ANGLE, which is pretty necessary right now.

On top of Apple deprecating OpenGL, MKXP has crashing issues from
the OpenGL -> Metal translation implemented in Apple Silicon macs.

It also enables things like the Steam Overlay and the use of the Metal
Performance HUD on macOS 13+. Vulkan seems to fix blitting issues on
Linux, removing the need for `enableBlitting` and `subImageFix`.

The particular build of ANGLE for MacOS is made using commit `91bfd02e7089b`, built with Metal support enabled. Both arm64 and x64 libraries were built using the `target_cpu` arg, then joined using the `lipo` tool.

The build for Windows and Linux is made using commit `a22f6857529b9`, based on my fork at https://github.com/Eblo/angle. This commit contains a fix for a Steam overlay bug.