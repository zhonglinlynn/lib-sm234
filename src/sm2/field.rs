use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};  //大端模式，数据的高字节保存在内存的低地址中
use num_bigint::BigUint;  //大正整数BigUint
use num_traits::Num;
use std::io::Cursor;

//定义结构体：模p系数
pub struct FieldCtx {
    modulus: FieldElem,  // p
    modulus_complete: FieldElem,  // -p
}


impl FieldCtx {
    /***********初始化结构体***********/
    pub fn new() -> FieldCtx {
        // p = 2^256 - 2^224 - 2^96 + 2^64 -1 = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
        let modulus = FieldElem::new([
            0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
        ]);
        let (modulus_complete, _borrow) = raw_sub(&FieldElem::zero(), &modulus); //大数相减0-p，存储负p和借位

        FieldCtx {
            modulus,  //p
            modulus_complete,  //-p
        }
    }

    /***********域加法 (a+b)mod p***********/
    pub fn add(&self, a: &FieldElem, b: &FieldElem) -> FieldElem {
        let (raw_sum, carry) = raw_add(a, b);  //调用大数相加

        if carry == 1 || raw_sum.ge(&self.modulus) { //如果进位，则调用大数相减，即modp
            let (sum, _borrow) = raw_sub(&raw_sum, &self.modulus);
            return sum;
        } else {
            return raw_sum;
        }
    }

    /***********域减法 (a-b)mod p***********/
    pub fn sub(&self, a: &FieldElem, b: &FieldElem) -> FieldElem {
        let (raw_diff, borrow) = raw_sub(a, b); //调用大数相减

        if borrow == 1 {  //如果借位，则调用大数相减，即mod(-p)
            let (diff, _borrow) = raw_sub(&raw_diff, &self.modulus_complete);
            return diff;
        } else {
            return raw_diff;
        }
    }

    /***********大整数快速减法 a:u64 - p:u32 ***********/
    //Guide书：2.2节：大数由W-bit的字表达，此处W=32
    // 论文：算法3快速减法；参考文献: http://ieeexplore.ieee.org/document/7285166/
    //快速减法：u64的大整数减u32的大素数 然后mod(p)
    #[inline]
    fn fast_reduction(&self, input: &[u32; 16]) -> FieldElem {
        let mut s: [FieldElem; 10] = [FieldElem::zero(); 10];
        let mut x: [u32; 16] = [0; 16];

        let mut i = 0;
        while i < 16 {  //i = 0,1,2,...,15,   x[0] = input[15] 大端字节转换为小端字节，低位放到0
            x[i] = input[15 - i];
            i = i + 1;
        }

        //计算S0到S9
        s[0] = FieldElem::new([x[7], x[6], x[5], x[4], x[3], x[2], x[1], x[0]]);
        s[1] = FieldElem::new([x[15], 0, 0, 0, 0, 0, x[15], x[14]]);
        s[2] = FieldElem::new([x[14], 0, 0, 0, 0, 0, x[14], x[13]]);
        s[3] = FieldElem::new([x[13], 0, 0, 0, 0, 0, 0, 0]);
        s[4] = FieldElem::new([x[12], 0, x[15], x[14], x[13], 0, 0, x[15]]);
        s[5] = FieldElem::new([x[15], x[15], x[14], x[13], x[12], 0, x[11], x[10]]);
        s[6] = FieldElem::new([x[11], x[14], x[13], x[12], x[11], 0, x[10], x[9]]);
        s[7] = FieldElem::new([x[10], x[11], x[10], x[9], x[8], 0, x[13], x[12]]);
        s[8] = FieldElem::new([x[9], 0, 0, x[15], x[14], 0, x[9], x[8]]);
        s[9] = FieldElem::new([x[8], 0, 0, 0, x[15], 0, x[12], x[11]]);

        //初始化：carry=0; sum=0;
        let mut carry: i32 = 0;
        let mut sum = FieldElem::zero();

        let (t, c) = raw_add(&sum, &s[1]); //sum+S^1
        sum = t;
        carry = carry + c as i32;
        let (t, c) = raw_add(&sum, &s[2]); //sum+S^2
        sum = t;
        carry = carry + c as i32;
        let (t, c) = raw_add(&sum, &s[3]); //sum+S^3
        sum = t;
        carry = carry + c as i32;
        let (t, c) = raw_add(&sum, &s[4]); //sum+S^4
        sum = t;
        carry = carry + c as i32;

        let (t, c) = raw_add(&sum, &sum); //2 * sum
        sum = t;
        carry = carry * 2 + c as i32;

        let (t, c) = raw_add(&sum, &s[5]); //sum+S^5
        sum = t;
        carry = carry + c as i32;
        let (t, c) = raw_add(&sum, &s[6]); //sum+S^6
        sum = t;
        carry = carry + c as i32;
        let (t, c) = raw_add(&sum, &s[7]); //sum+S^7
        sum = t;
        carry = carry + c as i32;
        let (t, c) = raw_add(&sum, &s[8]); //sum+S^8
        sum = t;
        carry = carry + c as i32;
        let (t, c) = raw_add(&sum, &s[9]); //sum+S^9
        sum = t;
        carry = carry + c as i32;

        let mut part3 = FieldElem::zero();
        let t: u64 = x[8] as u64 + x[9] as u64 + x[13] as u64 + x[14] as u64;  //t = m8+m9+m13+m14
        part3.value[5] = (t & 0xffffffff) as u32; //取t的低32bit
        part3.value[4] = (t >> 32) as u32; //取t的高32bit

        let (t, c) = raw_add(&sum, &s[0]); //sum+S^0 = sum+S^10
        sum = t;
        carry = carry + c as i32;

        let (t, c) = raw_sub(&sum, &part3);  //sum-part3
        sum = t;
        carry = carry - c as i32;

        while carry > 0 || sum.ge(&self.modulus) {
            let (s, b) = raw_sub(&sum, &self.modulus);  //如果有进位，则modp
            sum = s;
            carry -= b as i32;
        }

        sum
    }

    /***********域乘法 c = a * b ***********/
    pub fn mul(&self, a: &FieldElem, b: &FieldElem) -> FieldElem {
        let raw_prod = raw_mul(a, b); //调用大数相乘
        self.fast_reduction(&raw_prod) //调用c:u64-p:u32
    }

    /***********域元素平方 c = a * a ***********/
    #[inline(always)]
    pub fn square(&self, a: &FieldElem) -> FieldElem {
        self.mul(a, a) //调用域乘法
    }

      /***********域元素立方 c = a * a * a ***********/
    #[inline(always)]
    pub fn cubic(&self, a: &FieldElem) -> FieldElem {
        self.mul(a, &self.mul(a, a)) //调用2次域乘法
    }

     /***********域元素求逆 a^-1 ***********/
    // Extended Eulidean Algorithm(EEA) to calculate x^(-1) mod p；guide书底部62页，顶部41页，算法2.21
    // 扩展欧几里得方法计算逆元，参考文献 3.5节算法12：http://delta.cs.cinvestav.mx/~francisco/arith/julio.pdf
    pub fn inv(&self, x: &FieldElem) -> FieldElem {
        if x.eq(&FieldElem::zero()) {
            panic!("zero has no inversion in filed");
        }

        //步骤1：初始化u,v,A,C
        let mut u = *x;
        let mut v = self.modulus;
        let mut a = FieldElem::from_num(1);
        let mut c = FieldElem::zero();

        
        while !u.eq(&FieldElem::zero()) {
            //步骤2.1：如果u是奇数，则除以2
            if u.is_even() {
                u = u.div2(0);
                if a.is_even() {
                    a = a.div2(0);  // A/2
                } else {
                    let (sum, car) = raw_add(&a, &self.modulus);  // A+p/2
                    a = sum.div2(car);
                }
            }
            //步骤2.2：如果v是奇数，则除以2
            if v.is_even() {
                v = v.div2(0);
                if c.is_even() {
                    c = c.div2(0);  // C/2
                } else {
                    let (sum, car) = raw_add(&c, &self.modulus);  // C+p/2
                    c = sum.div2(car);
                }
            }

            //如果u>=v，则u=u-v, A=A-C
            if u.ge(&v) {
                u = self.sub(&u, &v);
                a = self.sub(&a, &c);
            } else {  //否则v=v-u, C=C-A
                v = self.sub(&v, &u);
                c = self.sub(&c, &a);
            }
        }
        return c;
    }

    /***********域元素负元 x = p - x ***********/
    pub fn neg(&self, x: &FieldElem) -> FieldElem {
        self.sub(&self.modulus, x)
    }

     /***********域元素指数 q^x，用于计算方程中x^3和y^2***********/
    fn exp(&self, x: &FieldElem, n: &BigUint) -> FieldElem {
        let u = FieldElem::from_biguint(n);

        let mut q0 = FieldElem::from_num(1);
        let mut q1 = x.clone();

        let mut i = 0;
        while i < 256 {
            let index = i as usize / 32;  //取商
            let bit = 31 - i as usize % 32;  //mod32，取余数

            let sum = self.mul(&q0, &q1);
            if (u.get_value(index) >> bit) & 0x01 == 0 {
                q1 = sum;
                q0 = self.square(&q0);
            } else {
                q0 = sum;
                q1 = self.square(&q1);
            }

            i = i + 1;
        }

        q0
    }


    // Square root of a field element开方计算，计算根号2次方
    pub fn sqrt(&self, g: &FieldElem) -> Result<FieldElem, bool> {
        // p = 4 * u + 3
        // u = u + 1
        let u = BigUint::from_str_radix(
            "28948022302589062189105086303505223191562588497981047863605298483322421248000",
            10,
        ).unwrap();

        let y = self.exp(g, &u);
        if self.square(&y).eq(g) {
            return Ok(y);
        }
        return Err(true);
    }
}

//定义结构体 域元素是8个u32,       8*32=256bit
#[derive(Copy, Clone)]
pub struct FieldElem {
    pub value: [u32; 8],
}

//大数相加：：输入2个大数，输出1个大数，计算(sum, carry) = a + b
//大端模式，高字节保存在内存的低地址中，所以从数据低端a.value[7]和b.value[7]开始相加，并存储进位
fn raw_add(a: &FieldElem, b: &FieldElem) -> (FieldElem, u32) {
    let mut sum = FieldElem::zero();//初始化sum = 0, carry = 0
    let mut carry: u32 = 0;

    //按顺序第7,6,5,4,3,2,1,0字节相加，存储进位
    let t_sum: u64 = a.value[7] as u64 + b.value[7] as u64 + carry as u64;
    sum.value[7] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = a.value[6] as u64 + b.value[6] as u64 + carry as u64;
    sum.value[6] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = a.value[5] as u64 + b.value[5] as u64 + carry as u64;
    sum.value[5] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = a.value[4] as u64 + b.value[4] as u64 + carry as u64;
    sum.value[4] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = a.value[3] as u64 + b.value[3] as u64 + carry as u64;
    sum.value[3] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = a.value[2] as u64 + b.value[2] as u64 + carry as u64;
    sum.value[2] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = a.value[1] as u64 + b.value[1] as u64 + carry as u64;
    sum.value[1] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = a.value[0] as u64 + b.value[0] as u64 + carry as u64;
    sum.value[0] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    (sum, carry)
}

//大数相减：输入2个大数，输出1个大数，计算(sum, carry) = a - b
//大端模式，高字节保存在内存的低地址中，所以从数据低端a.value[7]和b.value[7]开始相加，并存储进位
fn raw_sub(a: &FieldElem, b: &FieldElem) -> (FieldElem, u32) {
    let mut sum = FieldElem::new([0; 8]);
    let mut borrow: u32 = 0;
    let mut j = 0;

    while j < 8 {  //j=0,1,2,3,4,5,6,7
        let i = 7 - j;  //从低位开始作差，i = 7,6,5,4,3,2,1,0

        let t_sum: i64 = a.value[i] as i64 - b.value[i] as i64 - borrow as i64;

        if t_sum < 0 {  //如果小于零，则借位
            sum.value[i] = (t_sum + (1 << 32)) as u32;
            borrow = 1;
        } else {
            sum.value[i] = t_sum as u32;
            borrow = 0;
        }

        j = j + 1;
    }
    (sum, borrow)
}

//2个u32相乘
#[inline(always)]
fn u32_mul(a: u32, b: u32) -> (u64, u64) {
    let uv = a as u64 * b as u64;  //u32相乘，使用u64存储
    let u = uv >> 32;  //取高32bit
    let v = uv & 0xffffffff;  //取低32bit
    (u, v)
}

//大数相乘c=a*b：输入两个域元素，输出16个u32,   16*32=512=256+256
fn raw_mul(a: &FieldElem, b: &FieldElem) -> [u32; 16] {
    let mut local: u64 = 0;
    let mut carry: u64 = 0;
    let mut ret: [u32; 16] = [0; 16];

    let mut k = 0;
    while k < 15 {
        let index = 15 - k;
        let mut i = 0;
        while i < 8 {
            if i > k {
                break;
            }
            let j = k - i;
            if j < 8 {   //(UV) = C[i+j] + A[i]*B[j] +U,   C[i+j] = V；
                let (u, v) = u32_mul(a.value[7 - i], b.value[7 - j]);
                local += v;
                carry += u;
            }

            i = i + 1;
        }
        carry += local >> 32;
        local = local & 0xffffffff;
        ret[index] = local as u32;
        local = carry;
        carry = 0;

        k = k + 1;
    }
    ret[0] = local as u32;
    ret
}

impl FieldElem {
    //初始化域元素，8个u32
    pub fn new(x: [u32; 8]) -> FieldElem {
        FieldElem { value: x }
    }

    //域元素切片，把元素赋值给数组
    pub fn from_slice(x: &[u32]) -> FieldElem {
        let mut arr: [u32; 8] = [0; 8];
        arr[0] = x[0];
        arr[1] = x[1];
        arr[2] = x[2];
        arr[3] = x[3];
        arr[4] = x[4];
        arr[5] = x[5];
        arr[6] = x[6];
        arr[7] = x[7];
        FieldElem::new(arr)
    }

    //域元素赋值0
    pub fn zero() -> FieldElem {
        FieldElem::new([0; 8])
    }

    // 范围判断：self >= x，则返回ture
    pub fn ge(&self, x: &FieldElem) -> bool {
        let mut i = 0;
        while i < 8 {
            if self.value[i] < x.value[i] {
                return false;
            } else if self.value[i] > x.value[i] {
                return true;
            }

            i = i + 1;
        }
        return true;
    }

    //判断是否相等
    pub fn eq(&self, x: &FieldElem) -> bool {
        let mut i = 0;
        while i < 8 {
            if self.value[i] != x.value[i] {
                return false;
            }

            i = i + 1;
        }
        return true;
    }

    //大整数除以2
    pub fn div2(&self, carry: u32) -> FieldElem {
        let mut ret = FieldElem::zero();
        let mut carry = carry;

        let mut i = 0;
        while i < 8 {
            ret.value[i] = (carry << 31) + (self.value[i] >> 1);//除以2就是右移1位
            carry = self.value[i] & 0x01;
            i = i + 1;
        }
        ret
    }

    //奇数判断
    pub fn is_even(&self) -> bool {
        let x = self.value[7] & 0x01; //取最低位的个位
        if x == 0 {
            return true;
        } else {
            return false;
        }
    }

    // u32转换为u8，输入：8个u32=256bit，输出32个u8
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        for i in 0..8 {
            ret.write_u32::<BigEndian>(self.value[i]).unwrap();
        }
        ret
    }

    // u8转换为u32，输入：32个u8，输出8个u32
    pub fn from_bytes(x: &[u8]) -> FieldElem {
        if x.len() != 32 {
            panic!("a SCA-256 field element must be 32-byte long");
        }

        let mut elem = FieldElem::zero();
        let mut c = Cursor::new(x);
        for i in 0..8 {
            let x = c.read_u32::<BigEndian>().unwrap();
            elem.value[i] = x;
        }
        elem
    }

    //u8转换为biguint大整数
    pub fn to_biguint(&self) -> BigUint {
        let v = self.to_bytes();
        BigUint::from_bytes_be(&v[..])//Creates and initializes a BigUint.  The bytes are in big-endian byte order.
    }

    //大整数转换为u8字节
    pub fn from_biguint(bi: &BigUint) -> FieldElem {
        let v = bi.to_bytes_be();
        let mut num_v: Vec<u8> = Vec::new();
        let padding = 32 - v.len();
        for _i in 0..padding {
            num_v.push(0);
        }
        for i in v.iter() {
            num_v.push(*i);
        }
        FieldElem::from_bytes(&num_v[..])
    }

    //u64拆开为低位u32和高位u32
    pub fn from_num(x: u64) -> FieldElem {
        let mut arr: [u32; 8] = [0; 8];
        arr[7] = (x & 0xffffffff) as u32;  //取低32bit
        arr[6] = (x >> 32) as u32;  //取高32bit

        FieldElem::new(arr)
    }

    //u32大整数转换为字符串
    pub fn to_str(&self, radix: u32) -> String {
        let b = self.to_biguint();  //u8转换为biguint大整数
        b.to_str_radix(radix)//Returns the integer formatted as a string in the given radix.
    }

    //获得u32的值
    pub fn get_value(&self, i: usize) -> u32 {
        self.value[i]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::os::OsRng;
    use rand::Rng;

    #[test]
    fn test_add() {
        let ctx = FieldCtx::new();

        let a = FieldElem::from_num(1);
        let b = FieldElem::from_num(0xffffffff);
        let c = ctx.add(&a, &b);
        let c1 = FieldElem::from_num(0x100000000);
        assert!(c.eq(&c1));

        let b1 = ctx.add(&ctx.modulus, &b);
        assert!(b1.eq(&b));
    }

    #[test]
    fn test_sub() {
        let ctx = FieldCtx::new();

        let a = FieldElem::from_num(0xffffffff);
        let a1 = ctx.sub(&a, &ctx.modulus);
        assert!(a.eq(&a1));
    }

    fn rand_elem() -> FieldElem {
        let mut rng = OsRng::new().unwrap();
        let mut buf: [u32; 8] = [0; 8];
        for i in 0..8 {
            buf[i] = rng.next_u32();
        }

        let ret = FieldElem::new(buf);
        let ctx = FieldCtx::new();
        if ret.ge(&ctx.modulus) {
            let (ret, _borrow) = raw_sub(&ret, &ctx.modulus);
            return ret;
        }
        ret
    }

    #[test]
    fn add_sub_rand_test() {
        let ctx = FieldCtx::new();

        for _i in 0..20 {
            let a = rand_elem();
            let b = rand_elem();
            let c = ctx.add(&a, &b);
            let a1 = ctx.sub(&c, &b);
            assert!(a1.eq(&a));
        }
    }

    // test multiplilcations
    #[test]
    fn test_mul() {
        let ctx = FieldCtx::new();
        let x = raw_mul(&ctx.modulus, &ctx.modulus);
        let y = ctx.fast_reduction(&x);
        assert!(y.eq(&FieldElem::zero()));
    }

    #[test]
    fn test_div2() {
        let x = FieldElem::new([
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff,
        ]);
        let y = FieldElem::new([
            0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff,
        ]);
        assert!(y.eq(&x.div2(0)));
        assert!(x.eq(&x.div2(1)));
        assert!(!x.is_even());
        assert!(FieldElem::from_num(10).is_even());
    }

    #[test]
    fn test_inv() {
        let ctx = FieldCtx::new();
        let one = FieldElem::from_num(1);

        for _x in 1..100 {
            let x = rand_elem();
            let xinv = ctx.inv(&x);

            let y = ctx.mul(&x, &xinv);
            assert!(y.eq(&one));
        }
    }

    #[test]
    fn test_byte_conversion() {
        for _x in 1..100 {
            let x = rand_elem();
            let y = x.to_bytes();
            let newx = FieldElem::from_bytes(&y[..]);

            assert!(x.eq(&newx));
        }
    }

    #[test]
    fn test_bigint_conversion() {
        for _x in 1..100 {
            let x = rand_elem();
            let y = x.to_biguint();
            let newx = FieldElem::from_biguint(&y);

            assert!(x.eq(&newx));
        }
    }

    #[test]
    fn test_neg() {
        let ctx = FieldCtx::new();
        for _ in 0..100 {
            let x = rand_elem();
            let neg_x = ctx.neg(&x);
            let zero = ctx.add(&x, &neg_x);
            assert!(zero.eq(&FieldElem::zero()));
        }
    }

    #[test]
    fn test_sqrt() {
        let ctx = FieldCtx::new();

        for _ in 0..10 {
            let x = rand_elem();
            let x_2 = ctx.square(&x);
            let new_x = ctx.sqrt(&x_2).unwrap();

            assert!(x.eq(&new_x) || ctx.add(&x, &new_x).eq(&FieldElem::zero()));
        }
    }
}
