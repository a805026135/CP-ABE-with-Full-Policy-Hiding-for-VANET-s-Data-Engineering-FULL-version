import it.unisa.dia.gas.jpbc.*;
import java.util.*;

public class RevocationExample {

    // 在FullPolicyHidingCPABE类中添加或完善撤销方法
    public static class FullPolicyHidingCPABE {
        // ... 已有成员 ...

        /**
         * 属性撤销算法 (Algorithm 1)
         * @param ct 原始密文 (包含M, rho, 组件列表)
         * @param userId 请求解密的用户ID
         * @return 撤销后的密文 CT_f (尚未进行策略隐藏)
         */
        public RevokedCiphertext attributeRevoke(FullPolicyHidingCPABE.Ciphertext ct, String userId) {
            // 获取用户属性表TB中该用户的行
            Map<String, Boolean> userRow = userAttributeTable.getOrDefault(userId, new HashMap<>());
            List<FullPolicyHidingCPABE.CipherComponent> newComponents = new ArrayList<>();
            List<Element[]> newRows = new ArrayList<>();
            List<Integer> newRowIndices = new ArrayList<>(); // 原行号列表
            Map<Integer, String> newRho = new HashMap<>();

            // 遍历原始密文的每一行 (i从1到n)
            int n = ct.components.size();
            for (int i = 0; i < n; i++) {
                FullPolicyHidingCPABE.CipherComponent comp = ct.components.get(i);
                String attr = comp.attr;
                // 检查用户是否有该属性 (TB[Uid][rho(i)] == Y)
                boolean hasAttr = userRow.getOrDefault(attr, false);
                if (hasAttr) {
                    // 保留该行
                    newComponents.add(comp);
                    newRows.add(ct.M[i]); // 保存矩阵行向量
                    newRowIndices.add(i);
                    newRho.put(newComponents.size(), attr); // 新行号从1开始
                }
                // 否则跳过该行 (即撤销)
            }

            // 构建新的访问矩阵 M_{nf x l}
            int nf = newComponents.size();
            Element[][] newM = new Element[nf][ct.M[0].length];
            for (int i = 0; i < nf; i++) {
                newM[i] = newRows.get(i);
            }

            // 返回撤销后的密文结构 (尚未隐藏)
            return new RevokedCiphertext(newComponents, ct.C, ct.C_tilde, newM, newRho);
        }

        /**
         * 策略隐藏：基于撤销后的密文构建哈希链表HT
         * @param revokedCt 撤销后的密文
         * @param userId 用户ID (用于H2哈希)
         * @param timestamp 时间戳 (用于区分策略)
         * @return 最终密文 CT_f' 包含HT
         */
        public HiddenCiphertext policyStructureHiding(RevokedCiphertext revokedCt, String userId, String timestamp) {
            Map<Integer, List<RowInfo>> ht = new HashMap<>();
            int nf = revokedCt.components.size();

            for (int i = 0; i < nf; i++) {
                String attr = revokedCt.rho.get(i+1); // 行号从1开始
                // 计算 HIN_i = H2(rho_f(i), ID, t)
                String hashInput = attr + userId + timestamp;
                BigInteger hinBig = hashToZr(hashInput); // H2输出转为大整数
                int index = hinBig.mod(BigInteger.valueOf(1024)).intValue(); // 简化的索引范围

                // 存储行信息: 行号i+1 和 矩阵行向量
                RowInfo info = new RowInfo(i+1, revokedCt.M[i]);
                ht.computeIfAbsent(index, k -> new ArrayList<>()).add(info);
            }

            // 填充空槽为随机值 (论文要求，但我们简化演示)
            // 实际应遍历0..size-1，未填充的放入随机bytes

            return new HiddenCiphertext(revokedCt.components, revokedCt.C, revokedCt.C_tilde, ht, userId, timestamp);
        }

        // 内部类定义
        public static class RevokedCiphertext {
            public List<FullPolicyHidingCPABE.CipherComponent> components;
            public Element C, C_tilde;
            public Element[][] M;
            public Map<Integer, String> rho; // 新行号 -> 属性
            public RevokedCiphertext(List<FullPolicyHidingCPABE.CipherComponent> comps, Element c, Element ct, Element[][] m, Map<Integer, String> r) {
                components = comps; C = c; C_tilde = ct; M = m; rho = r;
            }
        }

        public static class HiddenCiphertext {
            public List<FullPolicyHidingCPABE.CipherComponent> components;
            public Element C, C_tilde;
            public Map<Integer, List<RowInfo>> HT;
            public String userId, timestamp;
            public HiddenCiphertext(List<FullPolicyHidingCPABE.CipherComponent> comps, Element c, Element ct, Map<Integer, List<RowInfo>> ht, String uid, String ts) {
                components = comps; C = c; C_tilde = ct; HT = ht; userId = uid; timestamp = ts;
            }
        }

        public static class RowInfo {
            public int rowIndex;
            public Element[] rowVector;
            public RowInfo(int idx, Element[] vec) { rowIndex = idx; rowVector = vec; }
        }
    }

    // 示例使用
    public static void main(String[] args) throws Exception {
        FullPolicyHidingCPABE scheme = new FullPolicyHidingCPABE();
        // 用户属性
        Set<String> userAttrs = new HashSet<>(Arrays.asList("police", "emergency"));
        String userId = "sp1";
        FullPolicyHidingCPABE.PrivateKey privKey = scheme.keyGen(userId, userAttrs);

        // 构建访问策略矩阵 (police AND emergency)
        int l = 2;
        Element[][] M = new Element[2][l];
        for (int i=0;i<2;i++) for(int j=0;j<l;j++) M[i][j] = scheme.Zr.newZeroElement();
        M[0][0] = scheme.Zr.newOneElement();
        M[1][0] = scheme.Zr.newOneElement(); M[1][1] = scheme.Zr.newOneElement();
        Map<Integer, String> rho = new HashMap<>();
        rho.put(1, "police");
        rho.put(2, "emergency");

        String plaintext = "Sensitive vehicle data";
        FullPolicyHidingCPABE.Ciphertext ct = scheme.encrypt(plaintext, M, rho);

        // 模拟撤销：假设用户缺少 "police" 属性 (例如被撤销)
        // 更新用户属性表: 将police设为false
        scheme.userAttributeTable.get(userId).put("police", false);

        // TA执行撤销
        FullPolicyHidingCPABE.RevokedCiphertext revokedCt = scheme.attributeRevoke(ct, userId);
        // 此时 revokedCt 中只包含 emergency 对应的行 (因为police被撤销)

        // 策略隐藏
        String timestamp = String.valueOf(System.currentTimeMillis());
        FullPolicyHidingCPABE.HiddenCiphertext hiddenCt = scheme.policyStructureHiding(revokedCt, userId, timestamp);

        // 后续外包解密...
        System.out.println("Revocation and hiding completed. Remaining rows: " + revokedCt.components.size());
    }
}