import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

public class Tongtai {
    public static TypeA1CurveGenerator pg = new TypeA1CurveGenerator(2, 128);
    public static PairingParameters typeA1Params = pg.generate();
    public static Pairing pairing = PairingFactory.getPairing(typeA1Params);
    public static Element generator = pairing.getG1().newRandomElement().getImmutable();
    //生成F的生成元f
    public static Element f = ElementUtils.getGenerator(pairing, generator, typeA1Params, 0, 2).getImmutable();
    //生成Gq的生成元gq
    public static Element gq = ElementUtils.getGenerator(pairing, generator, typeA1Params, 1, 2).getImmutable();
    //生成CL方案公私钥对
    public static Element sk = pairing.getZr().newRandomElement().getImmutable();
    public static Element pk = gq.powZn(sk);

    //假设用户A拥有秘密值a和c，用户B拥有秘密值b，用户A的目标是计算出ab+c的密文值
    //TongTai1方法能够得到ab的密文值，TongTai2方法能够得到ab+c的密文值
    public static void main(String[] args) {
        Element a = pairing.getZr().newRandomElement().getImmutable();
        Element b = pairing.getZr().newRandomElement().getImmutable();
        Element c = pairing.getZr().newRandomElement().getImmutable();
        //TongTai1方法求ab的密文值
        Element[] Encb = CLEncrypt(b);
        Element[] ans = Tongtai1(a, Encb);
        //TongTai2方法求ab+c的密文值
        Element[] res = Tongtai2(ans, c);

        //验证解密方法
        System.out.println(f.powZn(b));
        System.out.println(CLDecrypt(Encb));
        //验证同态加密方法
        System.out.println(f.powZn(a.mul(b).add(c)));
        System.out.println(CLDecrypt(res));
    }

    //CL加密方法，得到（gr的r次方，f的m次方乘以pk的r次方）
    public static Element[] CLEncrypt(Element b){
        //生成随机数r
        Element r = pairing.getZr().newRandomElement().getImmutable();
        //cl加密
        Element C1 = gq.powZn(r);
        Element C2 = f.powZn(b).mul(pk.powZn(r));
        return new Element[]{C1,C2};
    }

    //同态指数运算，得到（gq的ar次方，f的ab次方乘以pk的ar次方）
    public static Element[] Tongtai1(Element a, Element[] Encb){
        Element C1 = Encb[0].powZn(a);
        Element C2 = Encb[1].powZn(a);
        return new Element[]{C1,C2};
    }
    //同态密文乘法，得到（gr的ar次方，f的ab+c次方乘以pk的ar次）
    public static Element[] Tongtai2(Element[] ans, Element c){
        Element C1 = ans[0];
        Element C2 = ans[1].mul(f.powZn(c));
        return new Element[]{C1,C2};
    }

    //CL解密方法，得到f的b次方
    public static Element CLDecrypt(Element[] Encb){
        Element xx = Encb[0].powZn(sk);
        Element res = Encb[1].mul(xx.invert());
        return res;
    }
}
