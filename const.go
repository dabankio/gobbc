package gobbc

const Precision = 1000000

// TemplateType 模版类型
type TemplateType int16

// 模版类型
const (
	TemplateTypeMin TemplateType = iota
	TemplateTypeWeighted
	TemplateTypeMultisig //多重签名
	TemplateTypeFork
	TemplateTypeProof    //pow
	TemplateTypeDelegate //dpos
	TemplateTypeExchange
	TemplateTypeVote //dpos投票
	TemplateTypePayment
	TemplateTypeMax

	TemplateTypeMultisigPrefix = "02" //2 little endian

	// https://github.com/BigBang-Foundation/BigBang/wiki/通用Tx-vchData系列化定义
	// DataSzDescNone 表示没有strDescription
	DataSzDescNone uint8 = 0
)

// TemplateDataSpliter 使用,分隔多个template data
const TemplateDataSpliter = ","

func (typ TemplateType) String() string {
	switch typ {
	case TemplateTypeWeighted:
		return "weighted"
	case TemplateTypeMultisig:
		return "multisig"
	case TemplateTypeFork:
		return "fork"
	case TemplateTypeProof:
		return "proof"
	case TemplateTypeDelegate:
		return "delegate"
	case TemplateTypeExchange:
		return "exchange"
	case TemplateTypeVote:
		return "vote"
	case TemplateTypePayment:
		return "payment"
	default:
		return "unknown"
	}
}
