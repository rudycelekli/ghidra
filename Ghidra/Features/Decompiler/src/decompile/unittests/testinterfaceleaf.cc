/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "test.hh"
#include "ifaceterm.hh"

namespace ghidra {

struct ParserObservation {
  string command;
  vector<string> arguments;
};

class ObservedCommand : public IfaceBaseCommand {
  ParserObservation &observation;
  string name;
public:
  ObservedCommand(ParserObservation &result,const string &label)
    : observation(result), name(label) {}
  virtual void execute(istream &s) {
    observation.command = name;
    string word;
    while(s >> word)
      observation.arguments.push_back(word);
  }
};

// Exercise the public command dispatcher and terminal completion with the four
// actual leaf/child registration families used by the console.
static void checkParser(const string &line,const string &expected,
                        const vector<string> &arguments = vector<string>())
{
  ParserObservation observation;
  istringstream input(line + "\n");
  ostringstream output;
  IfaceTerm status("test> ",input,output);
  status.registerCom(new ObservedCommand(observation,"save"),"save");
  status.registerCom(new ObservedCommand(observation,"save signatures"),"save","signatures");
  status.registerCom(new ObservedCommand(observation,"restore"),"restore");
  status.registerCom(new ObservedCommand(observation,"print C"),"print","C");
  status.registerCom(new ObservedCommand(observation,"print C flat"),"print","C","flat");
  status.registerCom(new ObservedCommand(observation,"print C globals"),"print","C","globals");
  status.registerCom(new ObservedCommand(observation,"print C types"),"print","C","types");
  status.registerCom(new ObservedCommand(observation,"print C xml"),"print","C","xml");
  status.registerCom(new ObservedCommand(observation,"print inputs"),"print","inputs");
  status.registerCom(new ObservedCommand(observation,"print inputs all"),"print","inputs","all");
  status.registerCom(new ObservedCommand(observation,"callgraph build"),"callgraph","build");
  status.registerCom(new ObservedCommand(observation,"callgraph build quick"),"callgraph","build","quick");
  bool executed = status.runCommand();
  cerr << "INTERFACE_DISPATCH executed=" << executed << " command="
       << observation.command << " output=" << output.str() << endl;
  ASSERT_EQUALS(executed,!expected.empty());
  ASSERT_EQUALS(observation.command,expected);
  ASSERT(observation.arguments == arguments);
}

TEST(interface_leaf_save_argument) {
  checkParser("save state.xml","save",{"state.xml"});
}
TEST(interface_leaf_print_c_argument) {
  checkParser("print C extra","print C",{"extra"});
}
TEST(interface_leaf_print_inputs_argument) {
  checkParser("print inputs extra","print inputs",{"extra"});
}
TEST(interface_leaf_callgraph_argument) {
  checkParser("callgraph build extra","callgraph build",{"extra"});
}
TEST(interface_leaf_whitespace_rewind) {
  checkParser("save    ./state.xml  second third","save",{"./state.xml","second","third"});
}
TEST(interface_leaf_terminal_completion) {
  checkParser("save state.xml\t","save",{"state.xml"});
}
TEST(interface_child_save_signatures) {
  checkParser("save signatures signatures.xml","save signatures",{"signatures.xml"});
}
TEST(interface_child_print_flat) {
  checkParser("print C flat","print C flat");
}
TEST(interface_child_print_globals) {
  checkParser("print C globals","print C globals");
}
TEST(interface_child_print_types) {
  checkParser("print C types","print C types");
}
TEST(interface_child_print_xml) {
  checkParser("print C xml","print C xml");
}
TEST(interface_child_print_inputs_all) {
  checkParser("print inputs all","print inputs all");
}
TEST(interface_child_callgraph_quick) {
  checkParser("callgraph build quick","callgraph build quick");
}
TEST(interface_leaf_eof_controls) {
  checkParser("save","save");
  checkParser("restore state","restore",{"state"});
  checkParser("restore","restore");
  checkParser("print C","print C");
  checkParser("print inputs","print inputs");
  checkParser("callgraph build","callgraph build");
}
TEST(interface_ambiguous_prefix_control) {
  checkParser("print","");
}
TEST(interface_invalid_prefix_control) {
  checkParser("savex state.xml","");
}
TEST(interface_child_abbreviation_control) {
  checkParser("sa sig signatures.xml","save signatures",{"signatures.xml"});
}
TEST(interface_child_completion_control) {
  checkParser("save sig\t signatures.xml","save signatures",{"signatures.xml"});
}

} // End namespace ghidra
