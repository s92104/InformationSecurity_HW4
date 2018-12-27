import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.Scanner;

public class InformationSecurity_HW4 {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Key key=keyGerenate();
		System.out.println("p:"+key.p);
		System.out.println("q:"+key.q);
		System.out.println("a:"+key.a);
		System.out.println("b:"+key.b);
		System.out.println("d:"+key.d);
		
		//輸入
		Scanner scanner=new Scanner(System.in);
		System.out.print("Message:");
		String cmd=scanner.nextLine();
		while(!cmd.equals("0"))
		{			
			Signature signature=signatureGenerate(cmd, key);
			System.out.println("r:"+signature.r);
			System.out.println("s:"+signature.s);
			System.out.println("valid:"+signatureVerify(cmd, signature, key));
			
			System.out.print("Message:");
			cmd=scanner.nextLine();
		}
		
		
	}
	//產生大質數
	public static BigInteger generateBigPrime(int bit)
	{
		String prime;
		Random random=new Random();
		do {
			prime="1";
			for(int i=0;i<bit-2;i++)
				prime+=random.nextInt(2);
			prime+="1";
		} while (!MillerRabinTest(prime));
		return new BigInteger(prime,2);
	}	
	//Miller-Rabin Test
	public static boolean MillerRabinTest(String prime)
	{
		BigInteger n=new BigInteger(prime,2);
		BigInteger m =n.subtract(BigInteger.ONE);
		BigInteger k =BigInteger.ZERO;
		while(m.mod(new BigInteger("2")).equals(BigInteger.ZERO))
		{
			m=m.divide(new BigInteger("2"));
			k=k.add(BigInteger.ONE);
		}
		
		BigInteger a=new BigInteger("2");
		BigInteger b=a.modPow(m, n);
		if(!b.equals(BigInteger.ONE) && !b.equals(n.subtract(BigInteger.ONE)))
		{
			BigInteger i=BigInteger.ONE;
			while(i.compareTo(k)==-1 && !b.equals(n.subtract(BigInteger.ONE)))
			{
				b=b.modPow(new BigInteger("2"), n);
				if(b.equals(BigInteger.ONE))
					return false;
				i=i.add(BigInteger.ONE);
			}
			if(!b.equals(n.subtract(BigInteger.ONE)))
				return false;
		}
		return true;
	}
	public static boolean MillerRabinTest(BigInteger prime)
	{
		BigInteger n =prime;
		BigInteger m =n.subtract(BigInteger.ONE);
		BigInteger k =BigInteger.ZERO;
		while(m.mod(new BigInteger("2")).equals(BigInteger.ZERO))
		{
			m=m.divide(new BigInteger("2"));
			k=k.add(BigInteger.ONE);
		}
		
		BigInteger a=new BigInteger("2");
		BigInteger b=a.modPow(m, n);
		if(!b.equals(BigInteger.ONE) && !b.equals(n.subtract(BigInteger.ONE)))
		{
			BigInteger i=BigInteger.ONE;
			while(i.compareTo(k)==-1 && !b.equals(n.subtract(BigInteger.ONE)))
			{
				b=b.modPow(new BigInteger("2"), n);
				if(b.equals(BigInteger.ONE))
					return false;
				i=i.add(BigInteger.ONE);
			}
			if(!b.equals(n.subtract(BigInteger.ONE)))
				return false;
		}
		return true;
	}	
	//產生隨機大數
	public static BigInteger generateBigRandom(int bit,boolean even)
	{
		String num;
		Random random=new Random();
		num="1";
		for(int i=0;i<bit-2;i++)
			num+=random.nextInt(2);
		if(even)
			num+="0";
		else
			num+="1";
		return new BigInteger(num,2);
	}
	//找a,ord(a)=q
	public static BigInteger findOrdBase(BigInteger pow,BigInteger mod)
	{
		for(BigInteger i=new BigInteger("2");i.compareTo(mod.subtract(BigInteger.ONE))==-1;i=i.add(BigInteger.ONE))
		{
			BigInteger a=i.modPow(mod.subtract(BigInteger.ONE).divide(pow), mod);
			if(a.compareTo(BigInteger.ONE)!=0)
				return a;
		}
		return mod.subtract(BigInteger.ONE);
	}
	//Key Generation
	public static Key keyGerenate()
	{
		//p,q are prime//p-1|q 
		BigInteger q=generateBigPrime(160);
		BigInteger random;
		BigInteger p;
		do {
			random=generateBigRandom(864, true);
			p=q.multiply(random).add(BigInteger.ONE);
		} while (!MillerRabinTest(p));
		//ord(a)=q
		BigInteger a=findOrdBase(q, p);
		//choose private key//0<d<q
		BigInteger d;
		do {
			d=new BigInteger(160, new Random());
		} while (d.compareTo(BigInteger.ZERO)!=1 || d.compareTo(q)!=-1);			
		//public key
		BigInteger b=a.modPow(d, p);
		
		Key key=new Key(p,q,a,d,b);
		return key;
	}
	//Signature Generation
	public static Signature signatureGenerate(String message,Key key) 
	{
		BigInteger p=key.p;
		BigInteger q=key.q;
		BigInteger a=key.a;
		BigInteger d=key.d;
		//choose ephemeral key
		BigInteger e;
		do {
			e=new BigInteger(160, new Random());
		} while (e.compareTo(BigInteger.ZERO)!=1 || e.compareTo(q)!=-1);
		//r
		BigInteger r=a.modPow(e, p).mod(q);
		//sha
		MessageDigest sha;
		BigInteger shaNum=new BigInteger("0");
		try {
			sha = MessageDigest.getInstance("SHA-1");
			sha.update(message.getBytes());
			shaNum=new BigInteger(1,sha.digest());
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		//s
		BigInteger s=shaNum.add(d.multiply(r)).multiply(e.modInverse(q)).mod(q);
		//Signature
		Signature signature=new Signature(r, s);
		return signature;
	}
	//Signature Verification
	public static boolean signatureVerify(String message,Signature signature,Key key)
	{
		BigInteger r=signature.r;
		BigInteger s=signature.s;
		BigInteger q=key.q;
		BigInteger p=key.p;
		BigInteger a=key.a;
		BigInteger b=key.b;
		//1<=r<=q-1//1<=s<=q-1
		if(r.compareTo(BigInteger.ONE)==-1 || r.compareTo(q.subtract(BigInteger.ONE))==1 || s.compareTo(BigInteger.ONE)==-1 || s.compareTo(q.subtract(BigInteger.ONE))==1)
			return false;
		BigInteger w=s.modInverse(q);
		//sha
		MessageDigest sha;
		BigInteger shaNum=new BigInteger("0");
		try {
			sha = MessageDigest.getInstance("SHA-1");
			sha.update(message.getBytes());
			shaNum=new BigInteger(1,sha.digest());
			
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}		
		BigInteger i=w.multiply(shaNum).mod(q);
		BigInteger j=w.multiply(r).mod(q);
		BigInteger v=a.modPow(i, p).multiply(b.modPow(j, p)).mod(p).mod(q);
		if(v.compareTo(r)==0)
			return true;
		return false;
	}
}
