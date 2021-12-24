


use super::cipher::Sm4Cipher;

pub enum CipherMode {
    Cfb,  //CFB, Cipher feedback密文反馈模式：将上一段密文与下一段明文异或后，进行加密
    Ofb,  //OFB, Output feedback输出反馈模式：使用加密模块生成密钥流，密钥流与明文异或
    Ctr,  //CTR, Counter mode计数器模式：将块密码变为流密码。通过递增一个加密计数器以产生连续的密钥流
}

//定义结构体：密钥和加密模式
pub struct SM4CipherMode {
    cipher: Sm4Cipher,
    mode: CipherMode,
}

//xor异或函数：u8 ^ u8，输出u8
fn block_xor(a: &[u8], b: &[u8]) -> [u8; 16] {
    if a.len() != 16 {  //检测输入必须是16个u8
        panic!("the block size of a must be 16.")
    }
    if b.len() != 16 {  //检测输入必须是16个u8
        panic!("the block size of b must be 16.")
    }

    let mut out: [u8; 16] = [0; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out  //输出16个u8
}

//递增函数，Ctr模式需要
fn block_add_one(a: &mut [u8]) {
    let mut t;
    let mut carry = 1;

    for i in 0..16 {
        t = a[15 - i] as i32 + carry;  //每次加1

        if t == 256 {
            t = 0;
            carry = 1;
        } else {
            carry = 0
        }

        a[15 - i] = t as u8;
    }
}

impl SM4CipherMode {
    //初始化结构体
    pub fn new(key: &[u8], mode: CipherMode) -> SM4CipherMode {
        let cipher = Sm4Cipher::new(key);  //读取密钥
        SM4CipherMode {
            cipher,
            mode,
        }
    }

    //加密函数
    pub fn encrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        if iv.len() != 16 { //判断初始向量必须是128比特
            panic!("the iv of sm4 must be 16-byte long");
        }
        match self.mode {
            CipherMode::Cfb => self.cfb_encrypt(data, iv),
            CipherMode::Ofb => self.ofb_encrypt(data, iv),
            CipherMode::Ctr => self.ctr_encrypt(data, iv)
        }
    }

    //解密函数
    pub fn decrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        if iv.len() != 16 {
            panic!("the iv of sm4 must be 16-byte long");
        }
        match self.mode {
            CipherMode::Cfb => self.cfb_decrypt(data, iv),
            CipherMode::Ofb => self.ofb_encrypt(data, iv),
            CipherMode::Ctr => self.ctr_encrypt(data, iv)
        }
    }

    /**********cfb加密**********/
    fn cfb_encrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let block_num = data.len() / 16;  //明文数据每128比特为一个块
        let tail_len = data.len() - block_num * 16; //末端数据长度

        let mut out: Vec<u8> = Vec::new(); 
        let mut vec_buf: Vec<u8> = vec![0; 16]; 
        vec_buf.clone_from_slice(iv); 

        // 128数据块处理：cfb模式加密数据
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..]);  //调用加密函数，对异或值加密

            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);  //上一段密文与下一段明文异或计算
            for i in ct.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(&ct); //把异或值存入向量
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..]);  //调用加密函数，产生密文
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i]; //密文与明文异或计算
            out.push(b);  //存储异或结果
        }

        out  //输出异或结果
    }

     /**********cfb解密**********/
     //与cfb加密对称
    fn cfb_decrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..]);

            let ct = &data[i * 16..i * 16 + 16];
            let pt = block_xor(&enc, ct);
            for i in pt.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(ct);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..]);
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        out
    }


    /**********ofb加密**********/
    fn ofb_encrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..]);  //密钥对初始向量加密
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);  //加密结果异或明文data
            for i in ct.iter() {
                out.push(*i);  //存储异或结果
            }
            vec_buf.clone_from_slice(&enc);  //存储密钥对初始向量加密结果作为下一次加密的初始向量
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..]);
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        out
    }
    
    /**********ctr加密**********/
    fn ctr_encrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.resize(16, 0);
        vec_buf.clone_from_slice(iv);
        let mut out: Vec<u8> = Vec::new();

        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..]);  //对nonce和累加器加密，生成密钥流
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);  //密钥流与明文数据异或计算
            for i in ct.iter() {
                out.push(*i);  //存储异或结果
            }
            block_add_one(&mut vec_buf[..]);  //调用累加器
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..]);
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        out
    }
}

// TODO: AEAD in SM4
// pub struct SM4Gcm;

// Tests below

#[cfg(test)]
mod tests {
    use super::*;

    use rand::os::OsRng;
    use rand::Rng;

    fn rand_block() -> [u8; 16] {
        let mut rng = OsRng::new().unwrap();
        let mut block: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut block[..]);
        block
    }

    fn rand_data(len: usize) -> Vec<u8> {
        let mut rng = OsRng::new().unwrap();
        let mut dat: Vec<u8> = Vec::new();
        dat.resize(len, 0);
        rng.fill_bytes(&mut dat[..]);
        dat
    }

    #[test]
    fn test_driver() {
        test_ciphermode(CipherMode::Ctr);
        test_ciphermode(CipherMode::Cfb);
        test_ciphermode(CipherMode::Ofb);
    }


    fn test_ciphermode(mode: CipherMode) {
        let key = rand_block();
        let iv = rand_block();

        let cmode = SM4CipherMode::new(&key, mode);

        let pt = rand_data(10);
        let ct = cmode.encrypt(&pt[..], &iv);
        let new_pt = cmode.decrypt(&ct[..], &iv);
        assert_eq!(pt, new_pt);

        let pt = rand_data(100);
        let ct = cmode.encrypt(&pt[..], &iv);
        let new_pt = cmode.decrypt(&ct[..], &iv);
        assert_eq!(pt, new_pt);

        let pt = rand_data(1000);
        let ct = cmode.encrypt(&pt[..], &iv);
        let new_pt = cmode.decrypt(&ct[..], &iv);
        assert_eq!(pt, new_pt);
    }
}
