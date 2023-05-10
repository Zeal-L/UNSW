#ifndef COMP6771_VEC3_H
#define COMP6771_VEC3_H


struct vec3 {
    union {
        double x;
        double r;
        double s;
    };
    union {
        double y;
        double g;
        double t;
    };
    union {
        double z;
        double b;
        double p;
    };

    vec3() : x{0}, y{0}, z{0} {}
    vec3(double x) : x{x}, y{x}, z{x} {}
    vec3(double x, double y, double z) : x{x}, y{y}, z{z} {}
    vec3(const vec3 &other) = default;
    vec3(vec3 &&other) = delete;
    ~vec3() = default;
};


#endif // COMP6771_VEC3_H