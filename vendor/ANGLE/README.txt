Here lives Google's ANGLE, which is pretty necessary right now.

On top of Apple deprecating OpenGL, MKXP has crashing issues from
the OpenGL -> Metal translation implemented in Apple Silicon macs.

It also enables things like the Steam Overlay and the use of the Metal
Performance HUD on macOS 13+. Vulkan seems to fix blitting issues on
Linux, removing the need for `enableBlitting` and `subImageFix`.

The particular build of ANGLE is made using commit `a22f6857529b9`, based on my fork at https://github.com/Eblo/angle. This commit contains a fix for a Steam overlay bug.