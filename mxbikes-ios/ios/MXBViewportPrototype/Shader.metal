#include <metal_stdlib>
using namespace metal;
struct MXBOutput { float4 position [[position]]; float4 color; float2 uv; };
// C MXBGLVertex uses 40 bytes. The old unpacked Metal struct used 48.
vertex MXBOutput mxb_vertex(const device float *vertices [[buffer(0)]],uint i [[vertex_id]]){
 const device float *v=vertices+i*10u;
 MXBOutput o;
 o.position=float4(v[0],v[1],v[2],v[3]);
 // Convert OpenGL homogeneous clip depth [-w,+w] to Metal [0,+w].
 o.position.z=0.5f*o.position.z+0.5f*o.position.w;
 o.color=float4(v[4],v[5],v[6],v[7]);
 o.uv=float2(v[8],v[9]);
 return o;
}
fragment float4 mxb_fragment(MXBOutput v [[stage_in]],texture2d<float> tex [[texture(0)]],
                             constant uint *alpha [[buffer(0)]]){
 constexpr sampler sampleNearest(coord::normalized,filter::nearest,address::clamp_to_edge);
 float4 color=v.color*tex.sample(sampleNearest,v.uv);
 if(alpha[0]){
  float ref=as_type<float>(alpha[2]);
  bool pass=false;
  switch(alpha[1]){
   case 0x0200:pass=false;break;
   case 0x0201:pass=color.a<ref;break;
   case 0x0202:pass=color.a==ref;break;
   case 0x0203:pass=color.a<=ref;break;
   case 0x0204:pass=color.a>ref;break;
   case 0x0205:pass=color.a!=ref;break;
   case 0x0206:pass=color.a>=ref;break;
   case 0x0207:pass=true;break;
  }
  if(!pass)discard_fragment();
 }
 return color;
}
