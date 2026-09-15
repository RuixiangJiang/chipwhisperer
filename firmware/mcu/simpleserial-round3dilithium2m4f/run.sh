make clean PLATFORM=CW308_STM32F4 SS_VER=SS_VER_2_1
make PLATFORM=CW308_STM32F4 SS_VER=SS_VER_2_1
python3 run_dilithium_glitch.py --program
python3 run_dilithium_glitch.py --glitch --locate

python3 run_dilithium_glitch.py --glitch \
    --ext-min 18155 --ext-max 18155 --ext-step 1 \
    --width-center 4508 --offset-center 2352 --span 0 --step 1 \
    --repeats 500 --csv rate_18155.csv
python3 run_dilithium_glitch.py --glitch \
    --ext-min 18171 --ext-max 18171 --ext-step 1 \
    --width-center 4508 --offset-center 2352 --span 0 --step 1 \
    --repeats 500 --csv rate_18171.csv
