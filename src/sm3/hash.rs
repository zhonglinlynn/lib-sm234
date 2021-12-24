// Sample 1
// Input:"abc"
// Output:66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0

// Sample 2
// Input:"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
// Outpuf:debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732

#[inline(always)]  //内联属性，函数ff0：输入3个u32类型，输出1个u32
fn ff0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z  //3个u32的异或值
}

#[inline(always)]  //内联属性，函数ff1：输入3个u32类型，输出1个u32
fn ff1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (x & z) | (y & z)  //计算表达式
}

#[inline(always)]  //内联属性，函数gg0：输入3个u32类型，输出1个u32
fn gg0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z //3个u32的异或值
}

#[inline(always)] //内联属性，函数gg1：输入3个u32类型，输出1个u32
fn gg1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)  //计算表达式
}

#[inline(always)] //内联属性，函数p0：输入1个u32类型，输出1个u32
fn p0(x: u32) -> u32 {
    x ^ x.rotate_left(9) ^ x.rotate_left(17)  //循环左移0位、9位、17位
}

#[inline(always)] //内联属性，函数p1：输入1个u32类型，输出1个u32
fn p1(x: u32) -> u32 {
    x ^ x.rotate_left(15) ^ x.rotate_left(23)  //循环左移0位、15位、23位
}

#[inline(always)]  //内联属性，输入64个u8，基于其中4个u8，输出1个u32
fn get_u32_be(b: &[u8; 64], i: usize) -> u32 {
    let n: u32 = (b[i] as u32) << 24
                | (b[i + 1] as u32) << 16
                | (b[i + 2] as u32) << 8
                | (b[i + 3] as u32) << 0;
    n  //返回1个u32的n  n = [b[i], b[i+1], b[i+2], b[i+3]]，i=0，4，8，12，16，..., 60
}

static IV: [u32; 8] = [
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d,  0xb0fb0e4e,  //8个初始向量IV，每个向量8*4=32bit, 8*32=256bit初始向量
];

//定义结构体：摘要值、msg长度、消息msg
pub struct Sm3Hash {
    digest: [u32; 8],
    length: u64,
    unhandle_msg: Vec<u8>,
}

impl Sm3Hash {
	/****新建结构体****/
    pub fn new(data: &[u8]) -> Sm3Hash {
        let mut hash = Sm3Hash {  //摘要值、长度、未处理消息
            digest: IV,
            length: (data.len() << 3) as u64,//byte.len转换为bit.len需要乘以8.
            unhandle_msg: Vec::new(),
        };
        for i in data.iter() {  //.iter()遍历
            hash.unhandle_msg.push(*i);  //.push(*i)数据添加入Vec
        }

        hash  //hash结构体存储了初始向量，需要压缩的数据和数据长度
    }

	/****获得哈希值：输出32个u8数据，32*8=256****/
    pub fn get_hash(&mut self) -> [u8; 32] {
        let mut output: [u8; 32] = [0; 32];   //输出32个u8数据
        self.pad();
        let len = self.unhandle_msg.len();  //未处理消息长度
        let mut count: usize = 0;
        let mut buffer: [u8; 64] = [0; 64];//64*8=512

        while count * 64 != len {
            for i in (count * 64)..(count * 64 + 64) {  //0--63,    64--127, 每次处理64*8=512bit数据
                buffer[i - count * 64] = self.unhandle_msg[i];
            }
            self.update(&buffer);//buffer每次压缩512bit
            count += 1;
        }

        for i in 0..8 {
            output[i * 4]     = (self.digest[i] >> 24) as u8;
            output[i * 4 + 1] = (self.digest[i] >> 16) as u8;
            output[i * 4 + 2] = (self.digest[i] >> 8)  as u8;
            output[i * 4 + 3] = (self.digest[i] >> 0)  as u8;
        }

        output  //输出256bit摘要值，32个u8
    }

    /****消息填充为64字符的整数倍****/
    fn pad(&mut self) {
        self.unhandle_msg.push(0x80);  //在数据的末尾添加1；0x80=1000_0000
        let blocksize = 64;
        while self.unhandle_msg.len() % blocksize != 56 {  //最后一块数据长度不足448bits 则直接补0000_0000字节  448/56=8bit
            self.unhandle_msg.push(0x00);
        }

        for i in 0..8 { // last 64bits 将length放到unhandle_msg的尾部  448 + 64 = 512
            self.unhandle_msg.push((self.length >> 56-i*8 & 0xff) as u8);
        }

        if self.unhandle_msg.len() % 64 != 0 {  //检测是否为64字符的整数倍
            panic!("-------SM3 Pad: error msgLen ------");
        }
    }

	/****更新模块：消息扩展、计算压缩值****/
    fn update(&mut self, buffer: &[u8; 64]) {
		/****消息扩展：16个字，扩展为：68个字w、64个字w1****/
		let mut w: [u32; 68] = [0; 68];  //68个字w  68*32=2176
        let mut w1: [u32; 64] = [0; 64];  //64个字w1  64*32=2048
        for i in 0..68 {
            if i<16 {
                w[i] = get_u32_be(&buffer, i * 4);
            }
            else {
                w[i] = p1(w[i - 16] ^ w[i - 9] ^ w[i - 3].rotate_left(15)) ^ w[i - 13].rotate_left(7) ^ w[i - 6];
            }
        }
        for i in 0..64 {
            w1[i] = w[i] ^ w[i + 4];
        }

		/****消息压缩：8个寄存器：A,B,C,D,E,F,G,H****/
        let mut a = self.digest[0] as u32;
        let mut b = self.digest[1] as u32;
        let mut c = self.digest[2] as u32;
        let mut d = self.digest[3] as u32;
        let mut e = self.digest[4] as u32;
        let mut f = self.digest[5] as u32;
        let mut g = self.digest[6] as u32;
        let mut h = self.digest[7] as u32;

        let mut ss1: u32;
        let mut ss2: u32;
        let mut tt1: u32;
        let mut tt2: u32;

        for i in 0..64 {
            if i< 16 {
                ss1 = a
                .rotate_left(12)
                .wrapping_add(e)
                .wrapping_add(0x79cc4519u32.rotate_left(i as u32))
                .rotate_left(7);
                ss2 = ss1 ^ a.rotate_left(12);
                tt1 = ff0(a, b, c)
                    .wrapping_add(d)
                    .wrapping_add(ss2)
                    .wrapping_add(w1[i]);
                tt2 = gg0(e, f, g)
                    .wrapping_add(h)
                    .wrapping_add(ss1)
                    .wrapping_add(w[i]);
            }
            else {
                ss1 = a
                    .rotate_left(12)
                    .wrapping_add(e)
                    .wrapping_add(0x7a879d8au32.rotate_left(i as u32))
                    .rotate_left(7);
                ss2 = ss1 ^ a.rotate_left(12);
                tt1 = ff1(a, b, c)
                    .wrapping_add(d)
                    .wrapping_add(ss2)
                    .wrapping_add(w1[i]); //w1[i]
                tt2 = gg1(e, f, g)
                    .wrapping_add(h)
                    .wrapping_add(ss1)
                    .wrapping_add(w[i]);  //w[i]
            }

            d = c;
            c = b.rotate_left(9);
            b = a;
            a = tt1;
            h = g;
            g = f.rotate_left(19);
            f = e;
            e = p0(tt2);
        }

		//输出256bit摘要值
		//V(i+1) = ABCDEFGH+V(i)
        self.digest[0] ^= a ;
        self.digest[1] ^= b ;
        self.digest[2] ^= c ;
        self.digest[3] ^= d ;
        self.digest[4] ^= e ;
        self.digest[5] ^= f ;
        self.digest[6] ^= g ;
        self.digest[7] ^= h ;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lets_hash_1() {
        let string = String::from("abc");
        //let string = String::from("abcd");
        let s = string.as_bytes();
        let mut sm3 = Sm3Hash::new(s);
        let hash = sm3.get_hash();
        let standrad_hash: [u8; 32] = [
            0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10,
            0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b,
            0x8f, 0x4b, 0xa8, 0xe0,
        ];

        for i in 0..32 {
            assert_eq!(standrad_hash[i], hash[i]);
        }
    }

    #[test]
    fn lets_hash_2() {
        let string = String::from("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
        let s = string.as_bytes();
        let mut sm3 = Sm3Hash::new(s);
        let hash = sm3.get_hash();
        let standrad_hash: [u8; 32] = [
            0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e,
            0x5a, 0x4d, 0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3,
            0x9c, 0x0c, 0x57, 0x32,
        ];

        for i in 0..32 {
            assert_eq!(standrad_hash[i], hash[i]);
        }
    }
}
