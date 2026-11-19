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
 /* Fixed-function transforms and UVs go through original import names. */
 mxb_gl_reset(s);
 const float translation[3]={2.0f,0.0f,0.0f};
 const float scaling[3]={2.0f,1.0f,1.0f};
 const float texcoord[2]={0.25f,0.75f};
 if(!mxb_gl_dispatch_import(s,"OPENGL32.dll","glTranslatef",0,translation,3)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glScalef",0,scaling,3)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glBegin",MXB_GL_TRIANGLES,0,0)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glTexCoord2f",0,texcoord,2)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glVertex3f",0,p1,3)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glVertex3f",0,p0,3)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glVertex3f",0,p2,3)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glEnd",0,0,0))return 13;
 if(mxb_gl_vertex_count(s)!=3u)return 14;
 v=mxb_gl_vertices(s);
 if(fabsf(v[0].position[0]-4.0f)>.0001f||
    fabsf(v[1].position[0])>.0001f||
    fabsf(v[2].position[0]-2.0f)>.0001f||
    fabsf(v[0].uv[0]-.25f)>.0001f||
    fabsf(v[2].uv[1]-.75f)>.0001f)return 15;
 if(mxb_gl_dispatch_import(s,"OPENGL32.dll","glTexCoord2f",0,texcoord,3)!=0||
    mxb_gl_vertex_count(s)!=3u)return 16;
 /* OpenGL matrix stacks preserve parents; rotation uses a normalized axis. */
 mxb_gl_reset(s);
 const float shift[3]={2.0f,0.0f,0.0f};
 const float rotate[4]={90.0f,0.0f,0.0f,2.0f};
 const float stretch[3]={2.0f,1.0f,1.0f};
 if(!mxb_gl_dispatch_import(s,"OPENGL32.dll","glTranslatef",0,shift,3)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glPushMatrix",0,0,0)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glRotatef",0,rotate,4)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glScalef",0,stretch,3)||
    !mxb_gl_begin(s,MXB_GL_TRIANGLES)||
    !mxb_gl_vertex3f(s,1,0,0)||
    !mxb_gl_vertex3f(s,0,1,0)||
    !mxb_gl_vertex3f(s,-1,0,0)||
    !mxb_gl_end(s)||
    !mxb_gl_dispatch_import(s,"OPENGL32.dll","glPopMatrix",0,0,0)||
    !mxb_gl_begin(s,MXB_GL_TRIANGLES)||
    !mxb_gl_vertex3f(s,1,0,0)||
    !mxb_gl_vertex3f(s,0,1,0)||
    !mxb_gl_vertex3f(s,-1,0,0)||
    !mxb_gl_end(s))return 17;
 if(mxb_gl_vertex_count(s)!=6u)return 18;
 v=mxb_gl_vertices(s);
 if(fabsf(v[0].position[0]-2.0f)>.0001f||
    fabsf(v[0].position[1]-2.0f)>.0001f||
    fabsf(v[1].position[0]-1.0f)>.0001f||
    fabsf(v[2].position[1]+2.0f)>.0001f||
    fabsf(v[3].position[0]-3.0f)>.0001f||
    fabsf(v[3].position[1])>.0001f||
    fabsf(v[4].position[0]-2.0f)>.0001f||
    fabsf(v[4].position[1]-1.0f)>.0001f)return 19;
 if(mxb_gl_pop_matrix(s)!=0)return 20; /* underflow */
 /* Projection and modelview stacks must not affect one another. */
 if(!mxb_gl_matrix_mode(s,MXB_GL_PROJECTION)||
    !mxb_gl_push_matrix(s)||
    !mxb_gl_translatef(s,99,0,0)||
    !mxb_gl_pop_matrix(s)||
    !mxb_gl_matrix_mode(s,MXB_GL_MODELVIEW))return 21;
 mxb_gl_clear_frame(s);
 if(!mxb_gl_begin(s,MXB_GL_TRIANGLES)||
    !mxb_gl_vertex3f(s,1,0,0)||
    !mxb_gl_vertex3f(s,0,1,0)||
    !mxb_gl_vertex3f(s,-1,0,0)||
    !mxb_gl_end(s))return 22;
 if(mxb_gl_vertex_count(s)!=3u||
    fabsf(mxb_gl_vertices(s)[0].position[0]-3.0f)>.0001f)return 23;
 mxb_gl_reset(s);
 for(unsigned i=1u;i<MXB_GL_MATRIX_STACK_DEPTH;i++)
  if(!mxb_gl_push_matrix(s))return 24;
 if(mxb_gl_push_matrix(s)!=0)return 25; /* overflow */
 for(unsigned i=1u;i<MXB_GL_MATRIX_STACK_DEPTH;i++)
  if(!mxb_gl_pop_matrix(s))return 26;
 if(mxb_gl_pop_matrix(s)!=0)return 27; /* underflow */
 if(mxb_gl_rotatef(s,45,0,0,0)!=0||
    mxb_gl_rotatef(s,NAN,0,0,1)!=0)return 28;
 if(!mxb_gl_begin(s,MXB_GL_TRIANGLES))return 29;
 if(mxb_gl_push_matrix(s)!=0||
    mxb_gl_rotatef(s,90,0,0,1)!=0)return 30; /* no state edits in glBegin */
 mxb_gl_abort(s);
 mxb_gl_destroy(s);return 0;
}
