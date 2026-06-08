make -f Makefile.kyberprobe clean PLATFORM=CWLITEARM SS_VER=SS_VER_2_1 KYBER_IMPL=m4fspeed

make -f Makefile.kyberprobe all PLATFORM=CWLITEARM SS_VER=SS_VER_2_1 KYBER_IMPL=m4fspeed 2>&1 | tee build_kyberprobe_ctupload.log

python program_target.py ./simpleserial-kyberprobe-CWLITEARM.hex

python test_upload_ct_dec.py