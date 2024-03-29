local bytebuffer = include("bytebuffer/bytebuffer.lua")

local LJBC_VERSION = "1.0.0"
local ljbc = {}

-- Placeholder value used when a table of flat protos is transformed into a hierarchial proto
ljbc.child_placeholder = {}

ljbc.BcDumpFlags = {
	Be = 0x1,
	Strip = 0x2,
	Ffi = 0x4,
}

-- Type codes for the GC constants of a prototype - also includes the length for the Str type
ljbc.KgcType = {
	Child = 0,
	Tab = 1,
	I64 = 2,
	U64 = 3,
	Complex = 4,
	Str = 5,
}

ljbc.KtabType = {
	Nil = 0,
	False = 1,
	True = 2,
	Int = 3,
	Num = 4,
	Str = 5,
}

ljbc.ProtoFlags = {
	Child = 0x1,
	Vararg = 0x2,
	Ffi = 0x4,
	NoJit = 0x8,
	Iloop = 0x10,
	HasReturn = 0x20,
	FixupReturn = 0x40,
	ClcCount = 0x20,
	ClcBits = 3,
	ClcPoly = 0x20 * 3, --ClcCount * ClcBits
	UvLocal = 0x8000,
	UvImmutable = 0x4000,
}

ljbc.PrimitiveType = {
	[0] = nil, -- Unnecessary but oh well
	[1] = false,
	[2] = true,
}

ljbc.opcode_mapping = {
	[1] = {
		[0] = "ISLT",	"ISGE",	"ISLE",		"ISGT",		"ISEQV",	"ISNEV",
		"ISEQS",	"ISNES",	"ISEQN",	"ISNEN",	"ISEQP",	"ISNEP",
		"ISTC",		"ISFC",		"IST",		"ISF",		"MOV",		"NOT",
		"UNM",		"LEN",		"ADDVN",	"SUBVN",	"MULVN",	"DIVVN",
		"MODVN",	"ADDNV", 	"SUBNV",	"MULNV", 	"DIVNV",	"MODNV", 
		"ADDVV",	"SUBVV", 	"MULVV",	"DIVVV",	"MODVV",	"POW",
		"CAT",		"KSTR",		"KCDATA",	"KSHORT", 	"KNUM",		"KPRI",
		"KNIL",		"UGET", 	"USETV",	"USETS", 	"USETN",	"USETP",
		"UCLO",		"FNEW",		"TNEW",		"TDUP", 	"GGET",		"GSET",
		"TGETV",	"TGETS", 	"TGETB", 	"TSETV",	"TSETS",	"TSETB",
		"TSETM", 	"CALLM",	"CALL",		"CALLMT", 	"CALLT",	"ITERC",
		"ITERN",	"VARG", 	"ISNEXT",	"RETM",		"RET",		"RET0",
		"RET1",		"FORI",		"JFORI",	"FORL", 	"IFORL",	"JFORL",
		"ITERL",	"IITERL", 	"JITERL",	"LOOP",		"ILOOP",	"JLOOP",
		"JMP",		"FUNCF",	"IFUNCF",	"JFUNCF",	"FUNCV",	"IFUNCV",
		"JFUNCV",	"FUNCC",	"FUNCCW",
	},
	[2] = {
		[0] = "ISLT",	"ISGE",	"ISLE",		"ISGT",		"ISEQV",	"ISNEV",
		"ISEQS",	"ISNES",	"ISEQN",	"ISNEN",	"ISEQP",	"ISNEP",
		"ISTC",		"ISFC",		"IST",		"ISF",		"ISTYPE",	"ISNUM",
		"MOV",		"NOT",		"UNM",		"LEN",		"ADDVN",	"SUBVN",
		"MULVN",	"DIVVN",	"MODVN",	"ADDNV",	"SUBNV",	"MULNV",
		"DIVNV",	"MODNV",	"ADDVV",	"SUBVV",	"MULVV",	"DIVVV",
		"MODVV",	"POW",		"CAT",		"KSTR",		"KCDATA",	"KSHORT",
		"KNUM",		"KPRI",		"KNIL",		"UGET",		"USETV",	"USETS",
		"USETN",	"USETP",	"UCLO",		"FNEW",		"TNEW",		"TDUP",
		"GGET",		"GSET",		"TGETV",	"TGETS",	"TGETB",	"TGETR",
		"TSETV",	"TSETS",	"TSETB",	"TSETM",	"TSETR",	"CALLM",
		"CALL",		"CALLMT",	"CALLT",	"ITERC",	"ITERN",	"VARG",
		"ISNEXT",	"RETM",		"RET",		"RET0",		"RET1",		"FORI",
		"JFORI",	"FORL",		"IFORL",	"JFORL",	"ITERL",	"IITERL",
		"JITERL",	"LOOP",		"ILOOP",	"JLOOP",	"JMP",		"FUNCF",
		"IFUNCF",	"JFUNCF",	"FUNCV",	"IFUNCV",	"JFUNCV",	"FUNCC",
		"FUNCCW",
	},
}

function ljbc.opcode_to_name(op, bytecode_ver)
	local opcodes = ljbc.opcode_mapping[bytecode_ver]
	assert(istable(opcodes))

	return opcodes[op]
end

function ljbc.opname_to_opcode(opname, bytecode_ver)
	local opcodes = ljbc.opcode_mapping[bytecode_ver]
	assert(istable(opcodes))

	opname = string.upper(opname)

	for k, v in pairs(opcodes) do
		if v == opname then
			return k
		end
	end

	error("invalid opname given")
end

function ljbc.parse(bytecode)
	local buf = bytebuffer.new(bytecode)
	local chunk = {}

	-- Ensure the given bytecode has the magic
	assert(buf:read_string(3) == "\x1bLJ")

	-- Read the bytecode version
	chunk.version = buf:uint8()

	-- Do we support this bytecode version?
	assert(istable(ljbc.opcode_mapping[chunk.version]))

	-- Read the bytecode flags
	chunk.flags = ljbc.read_flags(buf)

	-- Read debug info if the bytecode isn't stripped
	local is_stripped = bit.band(chunk.flags, ljbc.BcDumpFlags.Strip) ~= 0

	chunk.name = is_stripped and "unknown" or buf:read_string(buf:uleb128())

	-- Read the protos from the bytecode
	chunk.protos = {}
	while buf:peek_byte() ~= 0 do
		table.insert(chunk.protos, ljbc.read_proto(buf, is_stripped, chunk.version))
	end

	-- It's the end of the protos+ block and the bytecode dump
	assert(buf:uint8() == 0 and buf:eof())

	return ljbc.protos_to_tree(chunk.protos), chunk
end

function ljbc.read_flags(buf)
	return buf:uleb128()
end

-- lengthU pdata
function ljbc.read_proto(buf, is_stripped, bytecode_ver)
	local proto_len = buf:uleb128()
	local start_pos = buf:get_pos()

	-- phead
	-- flagsB numparamsB framesizeB numuvB numkgcU numknU numbcU
	--	[debuglenU [firstlineU numlineU]]
	local proto = {
		flags = buf:uint8(),
		num_params = buf:uint8(),
		frame_size = buf:uint8(),
		num_uv = buf:uint8(),
		num_kgc = buf:uleb128(),
		num_kn = buf:uleb128(),
		num_ins = buf:uleb128(),
	}

	if not is_stripped then
		proto.dbg_len = buf:uleb128()

		if proto.dbg_len > 0 then
			proto.dbg_first_line = buf:uleb128()
			proto.dbg_num_lines = buf:uleb128()
		end
	end

	-- pdata
	-- bcinsW* uvdataH* kgc* knum* [debugB*]
	proto.ins = {}
	for i = 0, proto.num_ins - 1 do
		table.insert(proto.ins, i, ljbc.decode_ins(buf:uint32(), bytecode_ver))
	end

	proto.uv = {}
	for i = 0, proto.num_uv - 1 do
		table.insert(proto.uv, i, buf:uint16())
	end

	proto.consts = {}

	proto.num_children = 0
	for i = 0, proto.num_kgc - 1 do
		local kgc = ljbc.read_kgc(buf)
		local neg_index = -(ljbc.neg_index(i) + proto.num_kgc + 1)

		if kgc.type >= ljbc.KgcType.Str then
			table.insert(proto.consts, neg_index, kgc.value)
		elseif kgc.type == ljbc.KgcType.Tab then
			table.insert(proto.consts, neg_index, kgc.value)
		elseif kgc.type == ljbc.KgcType.Child then
			-- KgcType.Child means that this proto contains children
			-- We need to store the child proto(s) in the parents' protos const table with a negated index
			-- Protos are written deepest first, which means we're reading them deepest first

			proto.num_children = proto.num_children + 1
			table.insert(proto.consts, neg_index, ljbc.child_placeholder)
		else
			error("Unimplemented KgcType: " .. tostring(kgc.type))
		end
	end

	for i = 0, proto.num_kn - 1 do
		table.insert(proto.consts, i, ljbc.read_kn(buf))
	end

	if not is_stripped then
		-- Not too sure what this is used for
		proto.debug = buf:read_bytes(proto.dbg_len)
	end

	assert(start_pos + proto_len == buf:get_pos())

	return proto
end

-- kgctypeU { ktab | (loU hiU) | (rloU rhiU iloU ihiU) | strB* }
function ljbc.read_kgc(buf)
	local kgc = {}

	kgc.type = buf:uleb128()

	if kgc.type >= ljbc.KgcType.Str then
		local len = kgc.type - ljbc.KgcType.Str
		local str = buf:read_string(len)

		kgc.value = str
	elseif kgc.type == ljbc.KgcType.Tab then
		kgc.value = ljbc.read_ktab(buf)
	else
		-- This seems correct?
		-- LJ_HASFFI shouldn't be defined so we don't have to worry about the other types
		-- just like bcread_kgc() does in lj_bcread.c

		assert(kgc.type == ljbc.KgcType.Child,
			string.format("unimplemented kgc type: " .. tostring(kgc.type)))
	end

	return kgc
end

-- intU0 | (loU1 hiU)
function ljbc.read_kn(buf)
	local is_num = bit.band(buf:peek_byte(), 1) == 1
	local v = buf:uleb128_33()

	return is_num and bytebuffer.lo_hi_to_double(v, buf:uleb128()) or v
end

-- narrayU nhashU karray* khash*
function ljbc.read_ktab(buf)
	local ktab = {}

	local num_array = buf:uleb128()
	local num_hash = buf:uleb128()

	for i = 0, num_array - 1 do
		ktab[i] = ljbc.read_ktabk(buf)
	end

	for i = 0, num_hash - 1 do
		ktab[ljbc.read_ktabk(buf)] = ljbc.read_ktabk(buf)
	end

	return ktab
end

-- ktabtypeU { intU | (loU hiU) | strB* }
function ljbc.read_ktabk(buf)
	local typ = buf:uleb128()

	if typ >= ljbc.KtabType.Str then
		return buf:read_string(typ - ljbc.KtabType.Str)
	elseif typ == ljbc.KtabType.Int then
		return buf:uleb128()
	elseif typ == ljbc.KtabType.Num then
		return bytebuffer.lo_hi_to_double(buf:uleb128(), buf:uleb128())
	elseif typ == ljbc.KtabType.Nil then
		return nil
	elseif typ == ljbc.KtabType.False then
		return false
	elseif typ == ljbc.KtabType.True then
		return true
	end

	error("Unknown ktabk type: " .. tostring(typ))
end

-- Decodes a 32-bit instruction
function ljbc.decode_ins(ins, bytecode_ver)
	local ins_d = {
		opcode = bit.band(ins, 0xff),
		a = bit.band(bit.rshift(ins, 8), 0xff),
		c = bit.band(bit.rshift(ins, 16), 0xff),
		b = bit.band(bit.rshift(ins, 24), 0xff),
		d = bit.band(bit.rshift(ins, 16), 0xffff),
	}

	ins_d.opcode_name = ljbc.opcode_to_name(ins_d.opcode, bytecode_ver)

	return ins_d
end

-- Returns the negated index of index for indexing into the const table of a func
function ljbc.neg_index(index)
	return bit.bnot(index)
end

-- Replaces the child_placeholder values with the children
-- This modifies the input
function ljbc.protos_to_tree(protos)
	local len = #protos

	for k, proto in ipairs(protos) do
		if proto.num_children > 0 then
			local children = {}
			for i = k - 1, 1, -1 do
				if #children >= proto.num_children then
					break
				end

				local c = protos[i]
				if c ~= nil then
					table.insert(children, 1, c)
					protos[i] = nil
				end
			end
			assert(#children == proto.num_children)

			for i = -1, -0xffff, -1 do
				if proto.consts[i] == ljbc.child_placeholder then
					assert(children[1] ~= nil)
					proto.consts[i] = table.remove(children, 1)
					proto.consts[i].parent = proto
				end
			end
			assert(#children == 0)
		end
	end

	assert(ljbc.table_len_unseq(protos) == 1)

	return protos[len]
end

function ljbc.table_len_unseq(t)
	local len = 0

	for k, v in pairs(t) do
		len = len + 1
	end

	return len
end

return ljbc
