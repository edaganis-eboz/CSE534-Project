
# Need tables for regular communication, just over ip
echo "table_add MyIngress.ipv4_lpm MyIngress.forward 192.168.1.0/24 => 00:00:00:00:00:01 0" | simple_switch_CLI
echo "table_add MyIngress.ipv4_lpm MyIngress.forward 192.168.2.0/24 => 00:00:00:00:00:04 1" | simple_switch_CLI

# MACSEC tables
echo "table_add MyIngress.sectag_table MyIngress.forward 1111 => 00:00:00:00:00:04 1" | simple_switch_CLI #
# echo "table_add MyIngress.ipv4_lpm MyIngress.forward 192.168.2.0/24 => 00:00:00:00:00:04 1" | simple_switch_CLI