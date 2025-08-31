defmodule Hasty.Spec do
  @moduledoc false

  use Etiquette.Spec

  alias Hasty.Types.VarInt

  packet "Long Header Packet", id: :long_header_packet do
    @fdoc "The most significant bit (0x80) of byte 0 (the first byte) is set to 1 for long headers."
    field "Header Form", 1, fixed: 1

    @fdoc """
    The next bit (0x40) of byte 0 is set to 1, unless the packet is a Version Negotiation packet.
    Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded.
    A value of 1 for this bit allows QUIC to coexist with other protocols; see [RFC7983].
    """
    field "Fixed Bit", 1, fixed: 1

    @fdoc "The next two bits (those with a mask of 0x30) of byte 0 contain a packet type."
    field "Long Packet Type", 2

    @fdoc "The semantics of the lower four bits (those with a mask of 0x0f) of byte 0 are determined by the packet type."
    field "Type-Specific Bits", 4, id: :type_specific_bits

    @fdoc """
    The QUIC Version is a 32-bit field that follows the first byte.
    This field indicates the version of QUIC that is in use and determines how the rest of the protocol fields are interpreted.
    """
    field "Version", 32

    @fdoc """
    The byte following the version contains the length in bytes of the Destination Connection ID field that follows it.
    This length is encoded as an 8-bit unsigned integer.
    In QUIC version 1, this value MUST NOT exceed 20 bytes.
    Endpoints that receive a version 1 long header with a value larger than 20 MUST drop the packet.
    In order to properly form a Version Negotiation packet, servers SHOULD be able to read longer connection IDs from other QUIC versions.
    """
    field "Destination Connection ID Length", 8, id: :destination_connection_id_length

    @fdoc "The Destination Connection ID field follows the Destination Connection ID Length field, which indicates the length of this field."
    field "Destination Connection ID", 0..160, length_by: :destination_connection_id_length, length_in: :bytes

    @fdoc """
    The byte following the Destination Connection ID contains the length in bytes of the Source Connection ID field that follows it.
    This length is encoded as an 8-bit unsigned integer.
    In QUIC version 1, this value MUST NOT exceed 20 bytes.
    Endpoints that receive a version 1 long header with a value larger than 20 MUST drop the packet.
    In order to properly form a Version Negotiation packet, servers SHOULD be able to read longer connection IDs from other QUIC versions.
    """
    field "Source Connection ID Length", 8, id: :source_connection_id_length

    @fdoc "The Source Connection ID field follows the Source Connection ID Length field, which indicates the length of this field."
    field "Source Connection ID", 0..160, length_by: :source_connection_id_length, length_in: :bytes

    @fdoc "The remainder of the packet, if any, is type specific."
    field "Type-Specific Payload", (..), id: :type_specific_payload
  end

  packet "Initial Packet", id: :initial_packet, of: :long_header_packet do
    @fdoc "The next two bits (those with a mask of 0x30) of byte 0 contain a packet type."
    field "Long Packet Type", 2, fixed: 0

    @fdoc """
    Two bits (those with a mask of 0x0c) of byte 0 are reserved across multiple packet types.
    These bits are protected using header protection; see Section 5.4 of [QUIC-TLS].
    The value included prior to protection MUST be set to 0.
    An endpoint MUST treat receipt of a packet that has a non-zero value for these bits after
    removing both packet and header protection as a connection error of type PROTOCOL_VIOLATION.
    Discarding such a packet after only removing header protection can expose the endpoint to
    attacks; see Section 9.5 of [QUIC-TLS].
    """
    field "Reserved Bits", 2, part_of: :type_specific_bits

    @fdoc """
    In packet types that contain a Packet Number field, the least significant two bits (those with a
    mask of 0x03) of byte 0 contain the length of the Packet Number field, encoded as an unsigned
    two-bit integer that is one less than the length of the Packet Number field in bytes.
    That is, the length of the Packet Number field is the value of this field plus one.
    These bits are protected using header protection; see Section 5.4 of [QUIC-TLS].      
    """
    field "Packet Number Length", 2, id: :packet_number_length, part_of: :type_specific_bits

    @fdoc """
    A variable-length integer specifying the length of the Token field, in bytes.
    This value is 0 if no token is present.
    Initial packets sent by the server MUST set the Token Length field to 0; clients that receive
    an Initial packet with a non-zero Token Length field MUST either discard the packet or generate
    a connection error of type PROTOCOL_VIOLATION.
    """
    field "Token Length", (..), id: :token_length, decoder: &VarInt.decode/1, part_of: :type_specific_payload

    @fdoc "The value of the token that was previously provided in a Retry packet or NEW_TOKEN frame."
    field "Token", (..), length_by: :token_length, length_in: :bytes, part_of: :type_specific_payload

    @fdoc """
    This is the length of the remainder of the packet (that is, the Packet Number and Payload
    fields) in bytes, encoded as a variable-length integer (Section 16).
    """
    field "Length", (..), id: :length, decoder: &VarInt.decode/1, part_of: :type_specific_payload

    @fdoc """
    This field is 1 to 4 bytes long.
    The packet number is protected using header protection; see Section 5.4 of [QUIC-TLS].
    The length of the Packet Number field is encoded in the Packet Number Length bits of byte 0;
    see above.
    """
    field "Packet Number", 8..32, length_by: :packet_number_length, length_in: :bytes, part_of: :type_specific_payload

    field "Packet Payload", min(8), length_by: :length, length_in: :bytes, part_of: :type_specific_payload
  end
end
