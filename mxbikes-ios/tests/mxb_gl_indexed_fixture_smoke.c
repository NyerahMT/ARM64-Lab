#include "mxb_gl_indexed_probe.h"
#include <math.h>

static int approx(float a,float b){return fabsf(a-b)<0.0005f;}
int main(void){
 MXBGLSurface*s=mxb_gl_create();
 if(!s)return 1;
 if(!mxb_gl_indexed_fixture(s))return 2;
 if(mxb_gl_vertex_count(s)!=3u)return 3;
 const MXBGLVertex*v=mxb_gl_vertices(s);
 if(!approx(v[0].position[0],-.7f)||
    !approx(v[1].position[0],.7f)||
    !approx(v[2].position[1],.75f)||
    !approx(v[0].color[0],1.0f)||
    !approx(v[1].color[1],1.0f)||
    !approx(v[2].color[2],1.0f)||
    !approx(v[0].uv[0],.1f)||!approx(v[1].uv[0],.9f)||
    !approx(v[2].uv[1],.9f))return 4;
 mxb_gl_destroy(s);return 0;
}
