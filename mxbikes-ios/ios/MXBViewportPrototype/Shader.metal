#include <metal_stdlib>
using namespace metal;
struct MXBOutput { float4 position [[position]]; float4 color; float2 uv; };
// C MXBGLVertex is 40 bytes. An unpacked MSL float4/float4/float2
// struct has 16-byte alignment and a 48-byte stride; indexing it would
// corrupt every vertex after the first. Explicit scalar lanes match C.
vertex MXBOutput mxb_vertex(const device float *vertices [[buffer(0)]],uint i [[vertex_id]]){
 const device float *v=vertices+i*10u;
 MXBOutput o;
 o.position=float4(v[0],v[1],v[2],v[3]);
 // GL homogeneous clip depth [-w,+w] maps to Metal [0,+w].
 o.position.z=0.5f*o.position.z+0.5f*o.position.w;
 o.color=float4(v[4],v[5],v[6],v[7]);
 o.uv=float2(v[8],v[9]);
 return o;
}
fragment float4 mxb_fragment(MXBOutput v [[stage_in]],texture2d<float> tex [[texture(0)]]){
 constexpr sampler sampleNearest(coord::normalized,filter::nearest,address::clamp_to_edge);
 return v.color*tex.sample(sampleNearest,v.uv);
}
