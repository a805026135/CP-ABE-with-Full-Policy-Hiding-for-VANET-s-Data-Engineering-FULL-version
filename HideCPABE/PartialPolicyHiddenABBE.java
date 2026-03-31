package cn.edu.buaa.crypto.HideCPABE;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.security.MessageDigest;
import java.util.*;

/**
 * 部分策略隐藏的基于属性的广播加密方案（支持安全外包解密）
 * 参照论文：Partially policy-hidden attribute-based broadcast encryption with secure delegation in edge computing
 */
public class PartialPolicyHiddenABBE {

    // 双线性配对参数
    private Pairing pairing;
    private Field G1, GT, Zr;

    // 公开参数 PK
    public static class PublicParameters {
        Element g;           // G1的生成元
        Element h1, h2, h3, h4;
        Element tau;
        Element u, h, omega, v, vPrime, uPrime;
        Element[] g_i;       // g^{a^i}
        int maxUsers;        // 最大用户数m
        // 哈希函数和对称加密占位
        public Map<String, Element> attrNameToElement; // 属性名到随机群元素的映射（简化部分隐藏）
    }

    // 主私钥 MSK
    public static class MasterSecretKey {
        Element d1, d2, d3, d4, alpha, theta;
    }

    // 用户私钥 SK
    public static class SecretKey {
        Element K1, K2;
        List<AttributeKeyComponent> attrComponents;
        String userId;
        Set<String> attributes; // 属性名集合
    }

    // 每个属性对应的私钥组件
    public static class AttributeKeyComponent {
        String attrName;
        Element K_i1, K_i2, K_i3, K_i4, K_i5;
    }

    // 盲密钥 BK (用于外包解密)
    public static class BlindKey {
        Element K_prime, K2;
        List<AttributeKeyComponent> attrComponents;
    }

    // 恢复密钥 RK (用户本地保留)
    public static class RecoveryKey {
        Element delta;   // 随机数δ的逆元等，简化处理为密钥分量
    }

    // 密文 CT
    public static class Ciphertext {
        Element C_SE;           // 对称加密后的消息
        Element C;              // 会话密钥相关组件
        Element D;              // g^s
        Element F;              // 用于验证
        Map<String, Element> rowComponents; // 每个LSSS行对应的组件
        List<String> allowedUserIds;        // 直接撤销：允许的用户ID集合
        String accessPolicy;    // 用于展示的访问结构（属性名）
    }

    // 转换后的密文 CT' (由云服务器生成)
    public static class TransformedCiphertext {
        Element C0_prime, C1_prime;
    }

    private PublicParameters pk;
    private MasterSecretKey msk;

    public void setup(int maxUsers, int securityParameter) {
        // 生成Type A曲线配对 (对称配对)
        TypeACurveGenerator pg = new TypeACurveGenerator(securityParameter, 512);
        pairing = PairingFactory.getPairing(pg.generate());
        G1 = pairing.getG1();
        GT = pairing.getGT();
        Zr = pairing.getZr();

        pk = new PublicParameters();
        msk = new MasterSecretKey();

        // 随机生成主密钥组件
        Element g = G1.newRandomElement().getImmutable();
        pk.g = g;

        msk.d1 = Zr.newRandomElement().getImmutable();
        msk.d2 = Zr.newRandomElement().getImmutable();
        msk.d3 = Zr.newRandomElement().getImmutable();
        msk.d4 = Zr.newRandomElement().getImmutable();
        msk.alpha = Zr.newRandomElement().getImmutable();
        msk.theta = Zr.newRandomElement().getImmutable();

        pk.h1 = g.powZn(msk.d1).getImmutable();
        pk.h2 = g.powZn(msk.d2).getImmutable();
        pk.h3 = g.powZn(msk.d3).getImmutable();
        pk.h4 = g.powZn(msk.d4).getImmutable();
        pk.tau = g.powZn(msk.theta).getImmutable();

        // 随机元素 u, h, omega, v, v', u'
        pk.u = G1.newRandomElement().getImmutable();
        pk.h = G1.newRandomElement().getImmutable();
        pk.omega = G1.newRandomElement().getImmutable();
        pk.v = G1.newRandomElement().getImmutable();
        pk.vPrime = G1.newRandomElement().getImmutable();
        pk.uPrime = G1.newRandomElement().getImmutable();

        // 生成 g_i = g^{a^i}， a随机
        Element a = Zr.newRandomElement();
        pk.maxUsers = maxUsers;
        pk.g_i = new Element[2 * maxUsers + 1];
        Element aPow = Zr.newOneElement();
        for (int i = 1; i <= 2 * maxUsers; i++) {
            if (i == maxUsers + 1) continue;
            aPow = aPow.mulZn(a);  // a^i
            pk.g_i[i] = g.powZn(aPow).getImmutable();
        }

        // 为属性名分配随机群元素（用于部分隐藏：属性值在密文中隐藏，属性名作为公开标签）
        pk.attrNameToElement = new HashMap<>();
    }

    /**
     * 为用户生成私钥
     * @param userId 用户唯一标识
     * @param attributeSet 用户属性集合（属性名）
     */
    public SecretKey keyGen(String userId, Set<String> attributeSet) {
        SecretKey sk = new SecretKey();
        sk.userId = userId;
        sk.attributes = new HashSet<>(attributeSet);

        Element r = Zr.newRandomElement();
        Element rPrime = Zr.newRandomElement();

        // 计算 K1 = g^{alpha * ID * theta} * omega^{d1*d2*r + d3*d4*r'}
        Element exponentID = Zr.newElement(1).mulZn(msk.alpha).mulZn(ElementUtils.hashToZr(userId, Zr)).mulZn(msk.theta);
        Element K1 = pk.g.powZn(exponentID);
        Element expOmega = msk.d1.duplicate().mulZn(msk.d2).mulZn(r).add(msk.d3.duplicate().mulZn(msk.d4).mulZn(rPrime));
        K1 = K1.mul(pk.omega.powZn(expOmega)).getImmutable();
        sk.K1 = K1;

        // K2 = g^{d1*d2*r + d3*d4*r'}
        Element K2 = pk.g.powZn(expOmega).getImmutable();
        sk.K2 = K2;

        // 为每个属性生成组件
        sk.attrComponents = new ArrayList<>();
        for (String attr : attributeSet) {
            AttributeKeyComponent comp = new AttributeKeyComponent();
            comp.attrName = attr;

            Element r_i = Zr.newRandomElement();
            Element r_iPrime = Zr.newRandomElement();

            // 属性值在方案中表示为整数，这里简化为字符串的哈希值
            Element attrValue = ElementUtils.hashToZr(attr, Zr);
            Element base = (pk.u.powZn(attrValue)).mul(pk.h);
            Element exponentNegR = r.duplicate().negate();

            Element K_i_base = base.powZn(r_i).mul(pk.v.powZn(exponentNegR));
            comp.K_i1 = K_i_base.powZn(msk.d2).getImmutable();
            comp.K_i2 = K_i_base.powZn(msk.d1).getImmutable();
            comp.K_i3 = pk.g.powZn(msk.d1.duplicate().mulZn(msk.d2).mulZn(r_i).add(msk.d3.duplicate().mulZn(msk.d4).mulZn(r_iPrime))).getImmutable();
            comp.K_i4 = K_i_base.powZn(msk.d4).getImmutable();
            comp.K_i5 = K_i_base.powZn(msk.d3).getImmutable();

            sk.attrComponents.add(comp);
        }
        return sk;
    }

    /**
     * 生成外包解密所需的盲密钥BK和恢复密钥RK
     */
    public BlindKey outsourceKeyGen(SecretKey sk) {
        Element delta = Zr.newRandomElement();  // 随机盲化因子
        BlindKey bk = new BlindKey();
        RecoveryKey rk = new RecoveryKey();
        rk.delta = delta.duplicate();  // 实际恢复需要delta的逆，但简化处理

        // 盲化K1: K' = K1^{1/delta}，但论文中为K1^{delta}，根据外包协议调整
        Element deltaInv = delta.duplicate().invert();
        bk.K_prime = sk.K1.duplicate().powZn(deltaInv).getImmutable();
        bk.K2 = sk.K2.duplicate().getImmutable();

        bk.attrComponents = new ArrayList<>();
        for (AttributeKeyComponent comp : sk.attrComponents) {
            AttributeKeyComponent blindComp = new AttributeKeyComponent();
            blindComp.attrName = comp.attrName;
            blindComp.K_i1 = comp.K_i1.duplicate().powZn(deltaInv).getImmutable();
            blindComp.K_i2 = comp.K_i2.duplicate().powZn(deltaInv).getImmutable();
            blindComp.K_i3 = comp.K_i3.duplicate().powZn(deltaInv).getImmutable();
            blindComp.K_i4 = comp.K_i4.duplicate().powZn(deltaInv).getImmutable();
            blindComp.K_i5 = comp.K_i5.duplicate().powZn(deltaInv).getImmutable();
            bk.attrComponents.add(blindComp);
        }
        return bk;
    }

    /**
     * 加密算法
     * @param message 待加密消息（字符串）
     * @param policy LSSS访问策略 (矩阵M, 行到属性名的映射)
     * @param attrValues 每个属性名对应的属性值（用于部分隐藏）
     * @param allowedUserIds 允许解密的用户ID集合（直接撤销）
     */
    public Ciphertext encrypt(String message, Element[][] M, Map<Integer, String> rowToAttr,
                              Map<String, String> attrValues, Set<String> allowedUserIds) {
        Ciphertext ct = new Ciphertext();
        ct.allowedUserIds = new ArrayList<>(allowedUserIds);

        // 随机选择秘密s和向量v = (s, y2, ..., yn)
        Element s = Zr.newRandomElement();
        int n = M[0].length;
        Element[] v = new Element[n];
        v[0] = s;
        for (int i = 1; i < n; i++) v[i] = Zr.newRandomElement();

        // 计算每个LSSS行对应的λ_i = M_i * v
        int rows = M.length;
        Element[] lambda = new Element[rows];
        for (int i = 0; i < rows; i++) {
            lambda[i] = Zr.newZeroElement();
            for (int j = 0; j < n; j++) {
                lambda[i] = lambda[i].add(M[i][j].duplicate().mulZn(v[j]));
            }
            lambda[i] = lambda[i].getImmutable();
        }

        // 会话密钥：K = e(g, g)^{alpha * s}
        Element K = pairing.pairing(pk.g, pk.g).powZn(msk.alpha.duplicate().mulZn(s)).getImmutable();

        // 对称加密消息（实际使用AES，此处简化为异或哈希）
        byte[] msgBytes = message.getBytes();
        byte[] keyBytes = K.toBytes();
        byte[] cipherBytes = xorBytes(msgBytes, hashToBytes(keyBytes, msgBytes.length));
        ct.C_SE = G1.newElementFromBytes(cipherBytes).getImmutable(); // 占位，实际存储为字节数组

        // C = g^s, D = 用于验证的组件
        ct.D = pk.g.powZn(s).getImmutable();

        // 为每个LSSS行生成密文组件
        ct.rowComponents = new HashMap<>();
        for (int i = 0; i < rows; i++) {
            String attrName = rowToAttr.get(i+1); // 行号从1开始
            String attrVal = attrValues.get(attrName);
            Element attrValueHash = ElementUtils.hashToZr(attrVal, Zr);

            Element t_i = Zr.newRandomElement();
            // C_{i,1} = omega^{lambda_i} * v^{t_i}
            Element C_i1 = pk.omega.powZn(lambda[i]).mul(pk.v.powZn(t_i));
            // C_{i,2} = (u^{attrValue} * h)^{t_i}
            Element base = pk.u.powZn(attrValueHash).mul(pk.h);
            Element C_i2 = base.powZn(t_i);
            // C_{i,3} = g^{t_i}
            Element C_i3 = pk.g.powZn(t_i);
            // 部分隐藏：仅公开属性名，不公开属性值（属性值隐藏在C_i2中）
            ct.rowComponents.put(attrName + "_C1", C_i1.getImmutable());
            ct.rowComponents.put(attrName + "_C2", C_i2.getImmutable());
            ct.rowComponents.put(attrName + "_C3", C_i3.getImmutable());
        }

        // 广播撤销组件：为每个允许的用户ID生成g^{alpha * ID * theta}（用于用户私钥匹配）
        // 简化处理：将允许的用户ID集合编码进密文
        StringBuilder sb = new StringBuilder();
        for (String uid : allowedUserIds) sb.append(uid).append(",");
        ct.accessPolicy = sb.toString();

        return ct;
    }

    /**
     * 外包解密：云服务器使用盲密钥BK转换密文
     */
    public TransformedCiphertext decryptOut(Ciphertext ct, BlindKey bk, Map<String, String> userAttrValues) {
        // 检查用户属性集是否满足访问策略（简化：假设用户拥有密文中所有属性）
        // 实际需验证LSSS，这里只做演示
        TransformedCiphertext tct = new TransformedCiphertext();

        // 计算 e(g, g)^{alpha * s / delta}
        Element exponentDiv = msk.alpha.duplicate().mulZn(ct.D).getImmutable(); // 此处简化，正确应为配对
        // 实际应使用盲密钥中的组件与密文配对得到转换密文
        tct.C0_prime = GT.newOneElement();  // 占位
        tct.C1_prime = GT.newOneElement();
        return tct;
    }

    /**
     * 用户本地解密：使用恢复密钥RK从转换后的密文恢复消息
     */
    public String decryptUser(Ciphertext ct, TransformedCiphertext tct, RecoveryKey rk) {
        // 恢复会话密钥K = (C0_prime)^{delta}
        Element K = tct.C0_prime.duplicate().powZn(rk.delta);
        // 对称解密
        byte[] cipherBytes = ct.C_SE.toBytes();
        byte[] keyBytes = K.toBytes();
        byte[] plainBytes = xorBytes(cipherBytes, hashToBytes(keyBytes, cipherBytes.length));
        return new String(plainBytes);
    }

    // 辅助方法：字节异或
    private byte[] xorBytes(byte[] a, byte[] b) {
        int len = Math.min(a.length, b.length);
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) out[i] = (byte) (a[i] ^ b[i]);
        return out;
    }

    private byte[] hashToBytes(byte[] input, int length) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input);
            byte[] result = new byte[length];
            System.arraycopy(hash, 0, result, 0, Math.min(hash.length, length));
            return result;
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    // 工具类
    static class ElementUtils {
        static Element hashToZr(String str, Field Zr) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hash = md.digest(str.getBytes());
                return Zr.newElementFromBytes(hash).getImmutable();
            } catch (Exception e) { throw new RuntimeException(e); }
        }
    }

    // 主函数测试
    public static void main(String[] args) {
        PartialPolicyHiddenABBE scheme = new PartialPolicyHiddenABBE();
        scheme.setup(100, 160);  // 最大用户100，安全参数160

        // 用户属性
        Set<String> userAttrs = new HashSet<>(Arrays.asList("Department", "Role"));
        SecretKey sk = scheme.keyGen("user001", userAttrs);

        // 外包密钥
        BlindKey bk = scheme.outsourceKeyGen(sk);
        RecoveryKey rk = new RecoveryKey();
        rk.delta = Zr.newRandomElement(); // 实际应从 outsourceKeyGen 获取

        // 访问策略：简单AND门 (Department=IT AND Role=Admin)
        // LSSS矩阵 2x2
        Element[][] M = new Element[2][2];
        M[0][0] = scheme.Zr.newOneElement(); M[0][1] = scheme.Zr.newZeroElement();
        M[1][0] = scheme.Zr.newOneElement(); M[1][1] = scheme.Zr.newOneElement();
        Map<Integer, String> rowToAttr = new HashMap<>();
        rowToAttr.put(1, "Department");
        rowToAttr.put(2, "Role");
        Map<String, String> attrValues = new HashMap<>();
        attrValues.put("Department", "IT");
        attrValues.put("Role", "Admin");
        Set<String> allowedUsers = new HashSet<>(Arrays.asList("user001", "user002"));

        String plain = "Hello Edge Computing!";
        Ciphertext ct = scheme.encrypt(plain, M, rowToAttr, attrValues, allowedUsers);

        // 外包解密（模拟云端）
        TransformedCiphertext tct = scheme.decryptOut(ct, bk, attrValues);
        // 用户解密
        String decrypted = scheme.decryptUser(ct, tct, rk);

        System.out.println("原始消息: " + plain);
        System.out.println("解密消息: " + decrypted);
        System.out.println("解密成功: " + plain.equals(decrypted));
    }
}