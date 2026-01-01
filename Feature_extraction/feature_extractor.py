class FeatureExtractor:
    """
    Extracts IDS-relevant features from raw packet records.
    Input  : wide packet dictionary (from Network_extraction)
    Output : filtered + engineered feature dictionary
    """

    def _to_int(self, value, default = 0):
        try:
            return int(value)
        except(TypeError, ValueError):
            return default
            
    
    def extract(self, packet: dict) -> dict:
        features = {}

        
        # Basic numerical features
        features["packet_length"] = self._to_int(packet.get("packet_length", 0))
        features["inter_arrival_time"] = float(packet.get("inter_arrival_time", 0.0))
        features["ttl"] = self._to_int(packet.get("ttl", 0))

        # 
        # Protocol encoding
        
        protocol = packet.get("transport_layer")

        features["is_tcp"] = 1 if protocol == "TCP" else 0
        features["is_udp"] = 1 if protocol == "UDP" else 0
        features["is_icmp"] = 1 if protocol and "ICMP" in protocol else 0

        # 
        # Port features
        # 
        features["src_port"] = self._to_int(packet.get("src_port", -1))
        features["dst_port"] = self._to_int(packet.get("dst_port", -1))

        # 
        # TCP flag extraction
        # 
        tcp_flags = packet.get("tcp_flags")

        if tcp_flags:
            try:
                flags_int = int(tcp_flags, 16)
            except ValueError:
                flags_int = 0
        else:
            flags_int = 0

        features["syn_flag"] = 1 if flags_int & 0x02 else 0
        features["ack_flag"] = 1 if flags_int & 0x10 else 0
        features["fin_flag"] = 1 if flags_int & 0x01 else 0
        features["rst_flag"] = 1 if flags_int & 0x04 else 0

         
        
        dst_port = packet.get("dst_port")

        if isinstance(dst_port, int):
            features["is_well_known_port"] = 1 if 0 <= dst_port <= 1023 else 0
        else:
            features["is_well_known_port"] = 0


        return features
