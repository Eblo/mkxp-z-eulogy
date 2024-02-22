#ifndef RB_SHADER_H
#define RB_SHADER_H

#include "glstate.h"
#include "gl-util.h"
#include "binding-util.h"
#include "shader.h"
#include <map>

class CompiledShader : public ShaderBase
{
public:
    CompiledShader(const char *contents, VALUE args);
    CompiledShader(const char *contents, VALUE args, const char *vertContents);

    const char *getContents();
    const char *getVertContents();
    GLuint getProgram();
    std::map<const char *, GLint> getArgs();

private:
    void setupShaderSource(const char *contents, GLuint shader, bool vert);
    void compileShader(const char *contents, GLuint shader, GLuint program, bool vert);
    void setupArgs(VALUE args);

    const char *contents;
    const char *vertContents;
    std::map<const char *, GLint> args;
};
class CustomShader
{
public:
    CustomShader(CompiledShader* shader, VALUE args, VALUE texUnits);

    void applyArgs();

    GLint getUniform(const char *name);
    bool supportsVariable(const char *name);
    void setMatrix4(const char *name, const float value[16]);
    void setVec4(const char *name, const Vec4 &value);
    void setFloat(const char *name, const float value);
    void setInteger(const char *name, const int value);
    CompiledShader* getShader();

private:
    CompiledShader* shader;
    VALUE args;
    VALUE texUnits;
    unsigned int phase;
};

#endif