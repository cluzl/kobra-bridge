#!/usr/bin/env python3
"""Fail-closed Kobra cross-model G-code compatibility and derivation."""
import hashlib, importlib.util, pathlib, sys, tempfile
BASE=pathlib.Path(__file__).parent;sys.path.insert(0,str(BASE))
import kobra_models as models
spec=importlib.util.spec_from_file_location('kobra_gcode_compat',BASE/'kobra_gcode_compat.py')
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)

def fixture(model='Anycubic Kobra X',size=260,nozzle=.4,chamber=0,maxx=159,maxy=154,maxz=27,tools=(0,)):
 tool='\n'.join('T%d'%i for i in tools)
 chamber_cmd=f'M191 S{chamber}\n' if chamber else ''
 purge='''; PURGE LINE
M204 P500
SET_VELOCITY_LIMIT SQUARE_CORNER_VELOCITY=9
G1 Z0.75 F900
G1 X135 Y352 F18000
G1 Z.25 F900
G1 E0.8 F2400
G1 X205 Y352 E3.7
G1 Z0.5 F600
''' if model.endswith('S1 Max') else ''
 return f'''; HEADER_BLOCK_START
; max_z_height: {maxz}
; HEADER_BLOCK_END
; EXECUTABLE_BLOCK_START
EXCLUDE_OBJECT_DEFINE NAME=obj CENTER=100,100 POLYGON=[[10,10],[{maxx},10],[{maxx},{maxy}],[10,{maxy}]]
M73 P0 R1
;TYPE:Custom
{chamber_cmd}G9111 bedTemp=60 extruderTemp=220
M117
; print_bed_min = 0,0
; print_bed_max = {size},{size}
; print_bed_size = {size},{size}
; first_layer_print_min = 10,10
; first_layer_print_max = {maxx},{maxy}
; first_layer_print_size = {maxx-10},{maxy-10}
G90
G21
M83
; filament start gcode
M106 S0
{tool}
;LAYER_CHANGE
;Z:0.2
;HEIGHT:0.2
{purge}; AFTER_LAYER_CHANGE 0 @ 0.2mm
G1 X10 Y10 Z0.2 F3000
EXCLUDE_OBJECT_START NAME=obj
G1 X{maxx} Y{maxy} E1
G1 Z{maxz}
EXCLUDE_OBJECT_END NAME=obj
M106 S0
;TYPE:Custom
; filament end gcode
M400
M140 S0
M104 S0
M107
M84
M73 P100 R0
; EXECUTABLE_BLOCK_END
; CONFIG_BLOCK_START
; printer_model = {model}
; printer_settings_id = {model} 0.4 nozzle
; printable_area = 0x0,{size}x0,{size}x{size},0x{size}
; printable_height = {size}
; nozzle_diameter = {nozzle}
; gcode_flavor = klipper
; machine_start_gcode = old
; machine_end_gcode = old
; before_layer_change_gcode = old
; nozzle_temperature = 220
; hot_plate_temp = 60
; chamber_temperature = {chamber}
; support_chamber_temp_control = {1 if chamber else 0}
; filament_adaptive_volumetric_speed = 0
; filament_adhesiveness_category = 0
; filament_change_length = 0
; bed_temperature_formula = 0
; CONFIG_BLOCK_END
'''.encode()

def inspect(data):
 with tempfile.NamedTemporaryFile(suffix='.gcode') as f:
  f.write(data);f.flush();return m.inspect_gcode(f.name)

x=models.model_for_id('20030');s1=models.model_for_id('20025');smax=models.model_for_id('20029')
f=inspect(fixture())
assert f.source_model_id=='20030' and f.nozzle_mm==.4
# Progress represents the two real file passes: hash 0-50%, scan 50-100%.
with tempfile.NamedTemporaryFile(suffix='.gcode') as pf:
 pf.write(fixture());pf.flush();progress=[]
 m.inspect_gcode(pf.name,lambda done,total,stage:progress.append((done,total,stage)))
 assert progress and progress[-1][0]==progress[-1][1] and progress[-1][2]=='scanning',progress[-3:]
 assert any(stage=='hashing' for _,_,stage in progress) and any(stage=='scanning' for _,_,stage in progress)
 assert all(a[0]<=b[0] and a[1]==b[1] for a,b in zip(progress,progress[1:])),progress
assert f.bounds_min==(10.,10.,0.) and f.bounds_max==(159.,154.,27.),(f.bounds_min,f.bounds_max)
assert (f.max_nozzle_c,f.max_bed_c,f.max_chamber_c)==(220,60,0)
for target in (x,s1,smax):
 r=m.check_compatibility(f,target,.4,4);assert r.decision in ('native','convertible'),(target,r)
assert m.check_compatibility(inspect(fixture(maxx=255,maxy=255)),s1,.4,4).decision=='blocked'
assert m.check_compatibility(inspect(fixture(model='Anycubic Kobra S1 Max',size=350,maxx=300,maxy=300)),x,.4,4).decision=='blocked'
assert 'build volume' in ' '.join(m.check_compatibility(inspect(fixture(model='Anycubic Kobra S1 Max',size=350,maxx=300,maxy=300)),x,.4,4).reasons)
assert m.check_compatibility(inspect(fixture(nozzle=.6)),x,.4,4).decision=='blocked'
# A configured 0.6 mm target nozzle accepts files sliced for 0.6 mm.
assert m.check_compatibility(inspect(fixture(nozzle=.6)),x,.6,4).decision=='native'
# A configured target nozzle the model does not offer fails closed.
r_nozzle=m.check_compatibility(f,x,.35,4)
assert r_nozzle.decision=='blocked' and 'not supported' in ' '.join(r_nozzle.reasons),r_nozzle
assert m.check_compatibility(inspect(fixture(model='Anycubic Kobra S1 Max',size=350,chamber=60)),x,.4,4).decision=='blocked'
assert m.check_compatibility(inspect(fixture(tools=(0,1))),smax,.4,4).decision=='blocked','cross-model multicolour choreography is not safely rewritable'
assert m.check_compatibility(inspect(fixture(model='Unknown')),x,.4,4).decision=='blocked'
# Arc endpoints alone are insufficient: an I/J arc can bow outside the target.
arc=fixture().replace(b'G1 X159 Y154 E1',b'G2 X10 Y10 I250 J0 E1')
arc_f=inspect(arc);arc_r=m.check_compatibility(arc_f,s1,.4,4)
assert arc_r.decision=='blocked' and arc_f.bounds_max[0]>=510, (arc_f.bounds_max,arc_r)
# Unsupported R-form arcs fail closed rather than trusting incomplete bounds.
r_arc=fixture().replace(b'G1 X159 Y154 E1',b'G2 X159 Y154 R500 E1')
r_f=inspect(r_arc);r_report=m.check_compatibility(r_f,s1,.4,4)
assert r_report.decision=='blocked' and 'unsupported' in ' '.join(r_report.reasons),r_report
assert m.check_compatibility(r_f,x,.4,4).decision=='native','unsupported cross-model forms must not block a native file'
# Safe I/J arcs remain convertible and their feedrate is clamped for the target.
safe_arc=fixture().replace(b'G1 X159 Y154 E1',b'G2 X20 Y20 I5 J5 E1 F60000')
with tempfile.TemporaryDirectory() as d:
 src_arc=pathlib.Path(d)/'arc.gcode';out_arc=pathlib.Path(d)/'arc-out.gcode';src_arc.write_bytes(safe_arc)
 assert m.check_compatibility(m.inspect_gcode(src_arc),smax,.4,4).decision=='convertible'
 m.derive_gcode(src_arc,smax,out_arc)
 assert 'G2 X20 Y20 I5 J5 E1 F36000' in out_arc.read_text()
# G9111 in the body is a heater command too, not just a start-block marker.
hot=fixture().replace(b'G1 X159 Y154 E1',b'G9111 bedTemp=999 extruderTemp=999\nG1 X159 Y154 E1')
hot_f=inspect(hot);hot_r=m.check_compatibility(hot_f,s1,.4,4)
assert hot_r.decision=='blocked' and hot_f.max_nozzle_c==999 and hot_f.max_bed_c==999,(hot_f,hot_r)
# Derivation is deterministic, leaves source unchanged, swaps machine blocks and metadata.
with tempfile.TemporaryDirectory() as d:
 src=pathlib.Path(d)/'source.gcode';a=pathlib.Path(d)/'a.gcode';b=pathlib.Path(d)/'b.gcode';raw=fixture();src.write_bytes(raw)
 ra=m.derive_gcode(src,smax,a);rb=m.derive_gcode(src,smax,b)
 assert src.read_bytes()==raw and a.read_bytes()==b.read_bytes() and ra.sha256==rb.sha256
 out=a.read_text()
 assert '; KOBRA_BRIDGE_DERIVED target_model_id=20029' in out
 assert '; printer_model = Anycubic Kobra S1 Max' in out
 assert 'G1 X135 Y352 F18000' in out and 'M141 S0' in out
 assert '; printer_settings_id = Anycubic Kobra S1 Max 0.4 nozzle' in out
 # GoKlipper (S1 family) parser crashes on filament_colour_type; the others were
 # observed on real S1 Max files and stay. Only the known-fatal key is dropped.
 srcx=fixture().replace(b'; bed_temperature_formula = 0\n',b'; bed_temperature_formula = 0\n; filament_colour_type = "0"\n')
 src.write_bytes(srcx);m.derive_gcode(src,smax,a);outx=a.read_text()
 assert 'filament_colour_type' not in outx,'S1-family derived files must not carry filament_colour_type'
 m.derive_gcode(src,x,b);assert 'filament_colour_type' in b.read_text(),'Kobra X target keeps the key (its parser accepts it)'
 src.write_bytes(raw)
 # Reverse conversion strips Max purge/chamber end code and uses X metadata.
 src.write_bytes(fixture(model='Anycubic Kobra S1 Max',size=350,maxx=159,maxy=154,maxz=27))
 r=m.check_compatibility(m.inspect_gcode(src),x,.4,4);assert r.decision=='convertible',r
 m.derive_gcode(src,x,a);out=a.read_text()
 assert 'G1 X135 Y352 F18000' not in out and 'M141 S0' not in out
 assert '; printer_model = Anycubic Kobra X' in out
print('kobra gcode compatibility: all checks passed')
