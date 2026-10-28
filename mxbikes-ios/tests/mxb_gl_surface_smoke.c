#include "mxb_gl_surface.h"
#include <math.h>
int main(void) {
 MXBGLSurface *s=mxb_gl_create();if(!s)return 1;
 if(!mxb_gl_matrix_mode(s,MXB_GL_PROJECTION)||
    !mxb_gl_ortho(s,-2,2,-2,2,-10,10)||
    !mxb_gl_matrix_mode(s,MXB_GL_MODELVIEW)||
    !mxb_gl_translatef(s,1,0,0)||
    !mxb_gl_begin(s,MXB_GL_QUADS))return 2;
 if(!mxb_gl_vertex3f(s,-1,-1,0)||!mxb_gl_vertex3f(s,1,-1,0)||
    !mxb_gl_vertex3f(s,1,1,0)||!mxb_gl_vertex3f(s,-1,1,0)||
    !mxb_gl_end(s)||mxb_gl_vertex_count(s)!=6)return 3;
 const MXBGLVertex *v=mxb_gl_vertices(s);
 if(fabsf(v[0].position[0])>.0001f||
    fabsf(v[1].position[0]-1)>.0001f)return 4;
 mxb_gl_clear_frame(s);
 if(mxb_gl_vertex_count(s)!=0)return 5;
 if(mxb_gl_begin(s,0)!=0||mxb_gl_faults(s)!=1)return 6;
 mxb_gl_reset(s);
 if(mxb_gl_faults(s)!=0)return 7;
 const float p0[3]={-1,0,0},p1[3]={1,0,0},p2[3]={0,1,0};
 const float red[3]={1,0,0};
 const float proj[16]={1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1};
 if(!mxb_gl_dispatch_import(s,"OPENGL32.dll","glMatrixMode",MXB_GL_PROJECTION,0,0)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glLoadMatrixf",0,proj,16)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glMatrixMode",MXB_GL_MODELVIEW,0,0)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glLoadIdentity",0,0,0)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glColor3fv",0,red,3)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glBegin",MXB_GL_TRIANGLES,0,0)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glVertex3fv",0,p0,3)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glVertex3fv",0,p1,3)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glVertex3fv",0,p2,3)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glEnd",0,0,0))return 8;
 if(mxb_gl_vertex_count(s)!=3u)return 9;
 if(fabsf(mxb_gl_vertices(s)[1].position[0]-1.0f)>.0001f)return 10;
 if(mxb_gl_dispatch_import(s,"OPENGL32.dll","glTexImage2D",0,0,0)!=0)return 11;
 if(mxb_gl_dispatch_import(s,"steam_api64.dll","SteamAPI_Init",0,0,0)!=0)return 12;
 mxb_gl_destroy(s);return 0;
}
