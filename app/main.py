import socket
import struct
from dataclasses import dataclass
from typing import List, Tuple
import sys
import dataclasses


HEADER_STRUCT_FORMAT = ">HBBHHHH"
QUESTION_STRUCT_FORMAT = ">HH"
ANSWER_STRUCT_FORMAT = ">HHIH"
BIG = "big"


def name_to_bytes(name) -> bytes:
    byte_arr = bytearray()
    for part in name.split("."):
        byte_arr.extend(len(part).to_bytes(1, BIG))
        byte_arr.extend(part.encode())
    byte_arr.extend((0).to_bytes(1, BIG))
    return byte_arr



def parse_name(buffer, idx) -> Tuple[str, int]:
    res = []
    while buffer[idx] != 0:
        if (buffer[idx] >> 6) == 3:
            offset = int.from_bytes(buffer[idx : idx + 2]) & ((1 << 6) - 1)
            compressed_name, _ = parse_name(buffer, offset)
            res.extend(compressed_name.split("."))
            idx += 1  # increment only one because it'll increment again at the end of this fn
            break
        length = buffer[idx]
        res.append(buffer[idx + 1 : idx + length + 1].decode())
        idx = idx + length + 1
    return ".".join(res), idx + 1


@dataclass
class Header:
    id: int
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int
    @property
    def as_bytes(self) -> bytes:
        flag_a = self.qr << 7 | self.opcode << 3 | self.aa << 2 | self.tc << 1 | self.rd
        flag_b = self.ra << 7 | self.z << 4 | self.rcode
        return struct.pack(
            HEADER_STRUCT_FORMAT,
            self.id,
            flag_a,
            flag_b,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )
    @staticmethod
    def parse_buffer(buffer):
        (id, flag_a, flag_b, qdcount, ancount, nscount, arcount) = struct.unpack(
            HEADER_STRUCT_FORMAT, buffer[: struct.calcsize(HEADER_STRUCT_FORMAT)]
        )
        qr = (flag_a >> 7) & 1
        opcode = (flag_a >> 3) & ((1 << 4) - 1)
        aa = (flag_a >> 2) & 1
        tc = (flag_a >> 1) & 1
        rd = flag_a & 1
        ra = (flag_b >> 7) & 1
        z = (flag_b >> 4) & ((1 << 3) - 1)
        rcode = flag_b & ((1 << 4) - 1)
        return Header(
            id=id,
            qr=qr,
            opcode=opcode,
            aa=aa,
            tc=tc,
            rd=rd,
            ra=ra,
            z=z,
            rcode=rcode,
            qdcount=qdcount,
            ancount=ancount,
            nscount=nscount,
            arcount=arcount,
        )
    
@dataclass
class Question:
    name: str
    typ: int
    cls: int
    @property
    def as_bytes(self) -> bytes:
        return name_to_bytes(self.name) + struct.pack(
            QUESTION_STRUCT_FORMAT, self.typ, self.cls
        )
    @staticmethod
    def parse_buffer(buffer, idx):
        name, idx = parse_name(buffer, idx)
        typ, cls = struct.unpack(
            QUESTION_STRUCT_FORMAT,
            buffer[idx : idx + struct.calcsize(QUESTION_STRUCT_FORMAT)],
        )
        return Question(name=name, typ=typ, cls=cls), idx + struct.calcsize(
            QUESTION_STRUCT_FORMAT
        )
    
    
@dataclass
class Answer:
    name: str
    typ: int
    cls: int
    ttl: int
    length: int
    data: bytes
    @property
    def as_bytes(self) -> bytes:
        return (
            name_to_bytes(self.name)
            + struct.pack(
                ANSWER_STRUCT_FORMAT, self.typ, self.cls, self.ttl, self.length
            )
            + self.data
        )
    @staticmethod
    def parse_buffer(buffer, offset):
        name, idx = parse_name(buffer, offset)
        typ, cls, ttl, length = struct.unpack(
            ANSWER_STRUCT_FORMAT,
            buffer[idx : idx + struct.calcsize(ANSWER_STRUCT_FORMAT)],
        )
        idx += struct.calcsize(ANSWER_STRUCT_FORMAT)
        data = buffer[idx: idx + length]
        return Answer(name=name, typ=typ, cls=cls, ttl=ttl, length=length, data=data)
    

@dataclass
class DnsMessage:
    header: Header
    questions: List[Question]
    answers: List[Answer]


    @property
    def as_bytes(self) -> bytes:
        resp = bytearray()
        resp.extend(self.header.as_bytes)
        for q in self.questions:
            resp.extend(q.as_bytes)
        for a in self.answers:
            resp.extend(a.as_bytes)
        return resp

    @staticmethod
    def parse_buffer(buffer):
        header = Header.parse_buffer(buffer)
        questions = []
        answers = []
        offset = struct.calcsize(HEADER_STRUCT_FORMAT)
        for _ in range(header.qdcount):
            question, offset = Question.parse_buffer(buffer, offset)
            questions.append(question)

        for _ in range(header.ancount):
            answer, offset = Answer.parse_buffer(buffer, offset)
            answers.append(answer)

        return DnsMessage(header=header, questions=questions, answers=answers)
    

def create_header(msg: Header) -> bytes:
    flag_a = msg.qr << 7 | msg.opcode << 3 | msg.aa << 2 | msg.tc << 1 | msg.rd
    flag_b = msg.ra << 7 | msg.z << 4 | msg.rcode
    return struct.pack(
        ">HBBHHHH",
        msg.id,
        flag_a,
        flag_b,
        msg.qdcount,
        msg.ancount,
        msg.nscount,
        msg.arcount,
    )


def parse_forward_address():
    if len(sys.argv) >= 3 and sys.argv[1] == "--resolver":
        add, port = sys.argv[2].split(":")
        return add, int(port)
    return None, None


def forward_msg(buf, ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(buf, (ip, port))
    return sock.recvfrom(512)


def split_questions(msg: DnsMessage) -> List[DnsMessage]:
    if len(msg.questions) <= 1:
        return [msg]
    res = []
    for q in msg.questions:
        header = Header(**dataclasses.asdict(msg.header))
        header.qdcount = 1
        question = Question(**dataclasses.asdict(q))
        res.append(DnsMessage(header, questions=[question], answers=[]))
    return res



def main():
    forward_ip, forward_port = parse_forward_address()
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            recv_msg = DnsMessage.parse_buffer(buf)
            if forward_ip is not None:
                forward_resps = []
                for split_msg in split_questions(recv_msg):
                    forward_buf, forward_src = forward_msg(split_msg.as_bytes, forward_ip, forward_port)
                    forward_resp = DnsMessage.parse_buffer(forward_buf)
                    forward_resps.append(forward_resp)

                msg = None
                if len(forward_resps) == 1:
                    msg = forward_resps[0]
                else:
                    header = forward_resps[0].header
                    header.qdcount = len(forward_resps)
                    header.ancount = len(forward_resps)
                    questions = [msg.questions[0] for msg in forward_resps]
                    answers = [msg.answers[0] for msg in forward_resps]

                    msg = DnsMessage(header, questions, answers) 

                udp_socket.sendto(msg.as_bytes, source)
            
            else:
                questions = []
                answers = []
                for i, q in enumerate(recv_msg.questions):
                    questions.append(Question(name = q.name, typ = 1, cls = 1))
                    answers.append(Answer(name = q.name, typ = 1, cls =1 , ttl = 60, length = 4, data= b'\x08\x08\x08\x08'))

                header = Header(
                    id = recv_msg.header.id,
                    qr = 1,
                    opcode = recv_msg.header.opcode,
                    aa = 0,
                    tc = 0,
                    rd = recv_msg.header.rd,
                    ra = 0,
                    z = 0,
                    rcode = 0 if recv_msg.header.qdcount == 0 else 4,
                    qdcount = len(questions),
                    ancount = len(answers),
                    nscount= 0,
                    arcount = 0
                    
                )


            
                msg = DnsMessage(header, questions, answers)
                udp_socket.sendto(msg.as_bytes, source)
        except Exception as e:
            print(e)
            break

if __name__ == "__main__":
    main()