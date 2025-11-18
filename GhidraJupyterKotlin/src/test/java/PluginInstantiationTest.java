import GhidraJupyterKotlin.*;
import com.jediterm.core.typeahead.*;
import com.jediterm.terminal.ui.*;
import com.jediterm.terminal.ui.settings.*;
import ghidra.framework.plugintool.util.*;
import ghidra.test.*;
import org.junit.*;

import java.io.*;

public class PluginInstantiationTest extends AbstractGhidraHeadedIntegrationTest {

    @Test
    public void loadPluginTest() throws IOException, PluginException {
        var env = new TestEnv();
        env.addPlugin(JupyterKotlinPlugin.class);
    }
    @Test
    public void findClassTest() throws IOException, PluginException {
        var defaultSettings = new DefaultSettingsProvider();
        var widget = new JediTermWidget(60, 40, defaultSettings);
    }
}
