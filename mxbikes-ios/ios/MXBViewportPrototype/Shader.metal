#include <metal_stdlib>
using namespace metal;
struct MXBInput { float4 position; float4 color; float2 uv; };
struct MXBOutput { float4 position [[position]]; float4 color; float2 uv; };
vertex MXBOutput mxb_vertex(const device MXBInput *vertices [[buffer(0)]],uint i [[vertex_id]]){
 MXBOutput o; o.position=vertices[i].position;
 // GL homogeneous clip depth [-w,+w] maps to Metal [0,+w].
 o.position.z=0.5f*o.position.z+0.5f*o.position.w;
 o.color=vertices[i].color;o.uv=vertices[i].uv;return o;
}
fragment float4 mxb_fragment(MXBOutput v [[stage_in]],texture2d<float> tex [[texture(0)]]){
 constexpr sampler sampleNearest(coord::normalized,filter::nearest,address::clamp_to_edge);
 return v.color*tex.sample(sampleNearest,v.uv);
}
