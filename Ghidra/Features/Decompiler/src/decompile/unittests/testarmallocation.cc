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
#include "architecture.hh"
#include "modelrules.hh"
#include "test.hh"

namespace ghidra {

class ArmAllocationEnvironment {
  Architecture *architecture;
public:
  ArmAllocationEnvironment(void) : architecture((Architecture *)0) {}
  ~ArmAllocationEnvironment(void) { delete architecture; }
  Architecture *get(void) {
    if (architecture == (Architecture *)0) {
      istringstream input("<binaryimage arch=\"ARM:LE:32:v7:default\"></binaryimage>");
      DocumentStorage store;
      Document *doc = store.parseDocument(input);
      store.registerTag(doc->getRoot());
      architecture = ArchitectureCapability::getCapability("xml")->buildArchitecture("","",&cout);
      architecture->init(store);
    }
    return architecture;
  }
  const ParamEntry *stack(void) {
    const ParamListStandard *resource =
      (const ParamListStandard *)get()->protoModels["__stdcall_softfp"]->getInputResource();
    return resource->getStackEntry();
  }
};

static ArmAllocationEnvironment armAllocation;

TEST(arm_explicit_allocation_preserves_recognition) {
  Architecture *arch = armAllocation.get();
  const ParamEntry *entry = armAllocation.stack();
  int4 slot = 181;
  Address allocated = entry->getAllocationAddrBySlot(slot,4,4,arch);
  ASSERT(slot == 182);
  ASSERT(!allocated.isInvalid() && allocated.getOffset() == 724);
  ASSERT(entry->getSize() == 500);
  int4 recognizedSlot = 181;
  Address recognized = entry->getAddrBySlot(recognizedSlot,4,4,arch);
  ASSERT(recognized.isInvalid() && recognizedSlot == 181);
}

TEST(arm_explicit_allocation_alignment_and_justification) {
  Architecture *arch = armAllocation.get();
  const ParamEntry *entry = armAllocation.stack();
  int4 slot = 1;
  Address allocated = entry->getAllocationAddrBySlot(slot,8,8,arch);
  ASSERT(slot == 4 && allocated.getOffset() == 8);
  allocated = entry->getAllocationAddrBySlot(slot,1,1,true,arch);
  ASSERT(slot == 5 && allocated.getOffset() == 19);
}

TEST(arm_explicit_allocation_signed_stack_end) {
  Architecture *arch = armAllocation.get();
  const ParamEntry *entry = armAllocation.stack();
  int4 slot = 536870911;
  Address allocated = entry->getAllocationAddrBySlot(slot,4,4,arch);
  ASSERT(slot == 536870912 && allocated.getOffset() == 2147483644);
  Address invalid = entry->getAllocationAddrBySlot(slot,1,1,arch);
  ASSERT(invalid.isInvalid() && slot == 536870912);
}

TEST(arm_explicit_allocation_invalid_inputs_atomic) {
  Architecture *arch = armAllocation.get();
  const ParamEntry *entry = armAllocation.stack();
  int4 cases[][3] = { {-1,4,4}, {0,0,4}, {0,-1,4}, {0,4,0}, {0,4,3}, {0x7fffffff,4,4} };
  for(int4 i=0;i<6;++i) {
    int4 slot = cases[i][0];
    Address invalid = entry->getAllocationAddrBySlot(slot,cases[i][1],cases[i][2],arch);
    ASSERT(invalid.isInvalid() && slot == cases[i][0]);
  }
}

TEST(arm_explicit_allocation_default_process_entry_bounded) {
  Architecture *arch = armAllocation.get();
  const ParamListStandard *resource =
    (const ParamListStandard *)arch->protoModels["processEntry"]->getInputResource();
  const ParamEntry *entry = resource->getStackEntry();
  ASSERT(entry != (const ParamEntry *)0 && !entry->isUnboundedAllocation());
  int4 oldSlot = 181;
  int4 newSlot = 181;
  Address oldAddress = entry->getAddrBySlot(oldSlot,4,4,arch);
  Address newAddress = entry->getAllocationAddrBySlot(newSlot,4,4,arch);
  ASSERT(oldAddress == newAddress && oldSlot == newSlot);
}

TEST(arm_explicit_allocation_goto_failure_preserves_pieces) {
  Architecture *arch = armAllocation.get();
  const ParamListStandard *resource =
    (const ParamListStandard *)arch->protoModels["__stdcall_softfp"]->getInputResource();
  const ParamEntry *entry = resource->getStackEntry();
  GotoStack action(resource);
  vector<int4> status;
  resource->allocateStatus(status);
  status[entry->getGroup()] = 536870912;
  vector<int4> before = status;
  ParameterPieces result;
  result.addr = Address(arch->getStackSpace(),4);
  result.type = arch->types->getBase(1,TYPE_INT);
  result.flags = ParameterPieces::hiddenretparm;
  ParameterPieces snapshot = result;
  PrototypePieces proto = {};
  uint4 response = action.assignAddress(arch->types->getBase(4,TYPE_INT),proto,0,*arch->types,status,result);
  ASSERT(response == AssignAction::fail && status == before);
  ASSERT(result.addr == snapshot.addr && result.type == snapshot.type && result.flags == snapshot.flags);
}


TEST(arm_explicit_allocation_split_and_temp_rollback) {
  Architecture *arch = armAllocation.get();
  const ParamListStandard *resource =
    (const ParamListStandard *)arch->protoModels["__stdcall_softfp"]->getInputResource();
  const ParamEntry *entry = resource->getStackEntry();
  vector<int4> status;
  resource->allocateStatus(status);
  for(int4 i=0;i<status.size();++i) status[i] = -1;
  status[0] = 0;
  status[entry->getGroup()] = 181;
  MultiSlotAssign action(TYPECLASS_GENERAL,true,false,false,false,false,resource);
  ParameterPieces result = {};
  PrototypePieces proto = {};
  uint4 response = action.assignAddress(arch->types->getBase(8,TYPE_INT),proto,0,*arch->types,status,result);
  ASSERT(response == AssignAction::success && status[0] == -1 && status[entry->getGroup()] == 182);
  ASSERT(!result.addr.isInvalid() && result.addr.getSpace()->getType() == IPTR_JOIN);
  JoinRecord *record = result.addr.getSpace()->findJoin(result.addr.getOffset());
  ASSERT(record != (JoinRecord *)0 && record->numPieces() == 2);
  bool stack = false;
  for(int4 i=0;i<record->numPieces();++i) {
    const VarnodeData &piece = record->getPiece(i);
    ASSERT(piece.size == 4);
    stack |= piece.space == arch->getStackSpace() && piece.offset == 724;
  }
  ASSERT(stack);
  status[0] = 0;
  status[entry->getGroup()] = 536870912;
  vector<int4> before = status;
  ParameterPieces snapshot = result;
  response = action.assignAddress(arch->types->getBase(8,TYPE_INT),proto,0,*arch->types,status,result);
  ASSERT(response == AssignAction::fail && status == before);
  ASSERT(result.addr == snapshot.addr && result.type == snapshot.type && result.flags == snapshot.flags);
}

TEST(arm_explicit_allocation_extra_stack_failure_atomic) {
  Architecture *arch = armAllocation.get();
  const ParamListStandard *resource =
    (const ParamListStandard *)arch->protoModels["__stdcall_softfp"]->getInputResource();
  const ParamEntry *entry = resource->getStackEntry();
  vector<int4> status;
  resource->allocateStatus(status);
  status[entry->getGroup()] = 536870912;
  vector<int4> before = status;
  ExtraStack action(TYPECLASS_GENERAL,0,resource);
  ParameterPieces result = {};
  VarnodeData reg = arch->translate->getRegister("r0");
  result.addr = reg.getAddr();
  result.type = arch->types->getBase(4,TYPE_INT);
  result.flags = ParameterPieces::hiddenretparm;
  ParameterPieces snapshot = result;
  PrototypePieces proto = {};
  uint4 response = action.assignAddress(result.type,proto,0,*arch->types,status,result);
  ASSERT(response == AssignAction::fail && status == before);
  ASSERT(result.addr == snapshot.addr && result.type == snapshot.type && result.flags == snapshot.flags);
}


TEST(arm_explicit_allocation_large_inferred_offset_remains_bounded) {
  Architecture *arch = armAllocation.get();
  const ParamListStandard *resource =
    (const ParamListStandard *)arch->protoModels["__stdcall_softfp"]->getInputResource();
  Address observed(arch->getStackSpace(),2147483644);
  ASSERT(!resource->possibleParam(observed,4));
  ParamActive active(false);
  active.registerTrial(observed,4);
  active.getTrial(0).markActive();
  resource->fillinMap(&active);
  bool found = false;
  for(int4 i=0;i<active.getNumTrials();++i) {
    const ParamTrial &trial = active.getTrial(i);
    if (trial.getAddress() == observed) {
      found = true;
      ASSERT(!trial.isUsed());
    }
  }
  ASSERT(found && active.getNumTrials() < 200);
}


static void assertArmRuleRollback(const string &actions) {
  Architecture *arch = armAllocation.get();
  string xml = "<input><pentry minsize=\"1\" maxsize=\"4\"><register name=\"r0\"/></pentry>"
    "<pentry minsize=\"1\" maxsize=\"500\" align=\"4\" allocation=\"unbounded\">"
    "<addr space=\"stack\" offset=\"0\"/></pentry><rule><datatype name=\"any\"/>" + actions + "</rule></input>";
  istringstream stream(xml);
  XmlDecode decoder(arch);
  decoder.ingestStream(stream);
  ParamListStandard resource;
  vector<EffectRecord> effects;
  resource.decode(decoder,effects,true);
  vector<int4> status;
  resource.allocateStatus(status);
  ASSERT(status.size() == 2);
  status[1] = 536870912;
  ParameterPieces result = {};
  PrototypePieces proto = {};
  Datatype *dt = arch->types->getBase(4,TYPE_INT);
  uint4 response = resource.assignAddress(dt,proto,0,*arch->types,status,result);
  ASSERT(response == AssignAction::success);
  ASSERT(status[0] == -1 && status[1] == 536870912);
  ASSERT(result.addr == arch->translate->getRegister("r0").getAddr());
}

TEST(arm_explicit_allocation_precondition_rollback) {
  assertArmRuleRollback("<consume_extra storage=\"general\"/><goto_stack/>");
}

TEST(arm_explicit_allocation_sideeffect_rollback) {
  assertArmRuleRollback("<join storage=\"general\"/><extra_stack/>");
}

static void configureArmVarargs(FuncProto &proto) {
  Architecture *arch = armAllocation.get();
  ProtoModel *model = arch->protoModels["__stdcall_softfp"];
  proto.setInternal(model,arch->types->getTypeVoid());
  PrototypePieces pieces = {};
  pieces.model = model;
  pieces.outtype = arch->types->getTypeVoid();
  pieces.firstVarArgSlot = 185;
  for(int4 i=0;i<185;++i) {
    pieces.intypes.push_back(arch->types->getBase(4,TYPE_INT));
    pieces.innames.push_back("p" + to_string(i));
  }
  proto.setPieces(pieces);
  ASSERT(proto.isDotdotdot() && proto.isInputLocked() && proto.numParams() == 185);
}

TEST(arm_explicit_allocation_preserves_locked_varargs_prefix) {
  Architecture *arch = armAllocation.get();
  FuncProto proto;
  configureArmVarargs(proto);
  ParamActive active(true);
  for(int4 i=0;i<proto.numParams();++i) {
    ProtoParameter *param = proto.getParam(i);
    active.registerTrial(param->getAddress(),param->getSize());
    active.getTrial(i).markActive();
    active.getTrial(i).setFixedPosition(i);
  }
  Address inferred(arch->getStackSpace(),4096);
  active.registerTrial(inferred,4);
  active.getTrial(185).markActive();
  proto.deriveInputMap(&active);
  int4 declared = 0;
  bool inferredFound = false;
  for(int4 i=0;i<active.getNumTrials();++i) {
    const ParamTrial &trial = active.getTrial(i);
    if (trial.getFixedPosition() >= 0) {
      ASSERT(trial.isUsed() && !trial.isDefinitelyNotUsed());
      declared += 1;
    }
    else if (trial.getAddress() == inferred) {
      ASSERT(!trial.isUsed());
      inferredFound = true;
    }
  }
  ASSERT(declared == 185 && inferredFound && active.getNumTrials() < 200);
}

TEST(arm_explicit_allocation_rejects_untrusted_fixed_trials) {
  FuncProto proto;
  configureArmVarargs(proto);
  ProtoParameter *last = proto.getParam(184);
  for(int4 variant=0;variant<4;++variant) {
    ParamActive active(true);
    Address address = variant == 0 ? last->getAddress() + 4 : last->getAddress();
    int4 size = variant == 1 ? 2 : last->getSize();
    active.registerTrial(address,size);
    active.getTrial(0).markActive();
    active.getTrial(0).setFixedPosition(variant == 2 ? 185 : variant == 3 ? -1 : 184);
    proto.deriveInputMap(&active);
    bool found = false;
    for(int4 i=0;i<active.getNumTrials();++i) {
      const ParamTrial &trial = active.getTrial(i);
      if (trial.getAddress() == address && trial.getSize() == size) {
        ASSERT(!trial.isUsed());
        found = true;
      }
    }
    ASSERT(found && active.getNumTrials() < 200);
  }
}

TEST(arm_explicit_allocation_preserves_bounded_varargs_recovery) {
  Architecture *arch = armAllocation.get();
  ProtoModel *model = arch->protoModels["processEntry"];
  ASSERT(model != (ProtoModel *)0 && !model->getInputResource()->hasUnboundedAllocation());
  FuncProto proto;
  proto.setInternal(model,arch->types->getTypeVoid());
  ParameterPieces piece = {};
  piece.addr = Address(arch->getStackSpace(),724);
  piece.type = arch->types->getBase(4,TYPE_INT);
  proto.setParam(0,"declared",piece);
  proto.setInputLock(true);
  proto.setDotdotdot(true);
  ParamActive active(true);
  active.registerTrial(piece.addr,4);
  active.getTrial(0).markActive();
  active.getTrial(0).setFixedPosition(0);
  proto.deriveInputMap(&active);
  ASSERT(active.getNumTrials() == 1 && !active.getTrial(0).isUsed());
}

TEST(arm_explicit_allocation_preserves_unlocked_recovery) {
  FuncProto proto;
  configureArmVarargs(proto);
  proto.setInputLock(false);
  ProtoParameter *last = proto.getParam(184);
  ParamActive active(true);
  active.registerTrial(last->getAddress(),last->getSize());
  active.getTrial(0).markActive();
  active.getTrial(0).setFixedPosition(184);
  proto.deriveInputMap(&active);
  ASSERT(active.getNumTrials() == 1 && !active.getTrial(0).isUsed());
}
} // namespace ghidra
