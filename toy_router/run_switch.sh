# compile
p4c-bm2-ss main.p4 --p4runtime-files build/p4info.txt
simple_switch_grpc -i 0@enp0s3 -i 1@enp0s8 main.json &