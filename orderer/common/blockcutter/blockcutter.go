/*
Copyright IBM Corp. All Rights Reserved.
 
SPDX-License-Identifier: Apache-2.0
*/
 
package blockcutter
 
import (
    "math/big"
    "crypto/rand"
    "time"
    "encoding/json"
    "strings"
    cb "github.com/hyperledger/fabric-protos-go/common"
    "github.com/hyperledger/fabric/common/channelconfig"
    "github.com/hyperledger/fabric/common/flogging"
    pb "github.com/hyperledger/fabric-protos-go/peer"
    "github.com/golang/protobuf/proto"
)
 
var logger = flogging.MustGetLogger("orderer.common.blockcutter")
 
type OrdererConfigFetcher interface {
    OrdererConfig() (channelconfig.Orderer, bool)
}
 
// Receiver defines a sink for the ordered broadcast messages
type Receiver interface {
    // Ordered should be invoked sequentially as messages are ordered
    // Each batch in `messageBatches` will be wrapped into a block.
    // `pending` indicates if there are still messages pending in the receiver.
    Ordered(msg *cb.Envelope) (messageBatches [][]*cb.Envelope, pending bool)
 
    // Cut returns the current batch and starts a new one
    Cut() []*cb.Envelope
}
 
type receiver struct {
    sharedConfigFetcher   OrdererConfigFetcher
    pendingBatch          []*cb.Envelope
    pendingBatchSizeBytes uint32
 
    PendingBatchStartTime time.Time
    ChannelID             string
    Metrics               *Metrics
}
 
// NewReceiverImpl creates a Receiver implementation based on the given configtxorderer manager
func NewReceiverImpl(channelID string, sharedConfigFetcher OrdererConfigFetcher, metrics *Metrics) Receiver {
    return &receiver{
        sharedConfigFetcher: sharedConfigFetcher,
        Metrics:             metrics,
        ChannelID:           channelID,
    }
}
func generateRandomInRange(min, max int64) *big.Int {
    diff := max - min
    randNum, err := rand.Int(rand.Reader, big.NewInt(diff))
    if err != nil {
        panic(err)
    }
    return new(big.Int).Add(randNum, big.NewInt(min))
}
// Paillier decryption function
func DecryptPaillier(ciphertext *big.Int, lambda *big.Int, mu *big.Int, n *big.Int) *big.Int {
    nSquare := new(big.Int).Mul(n, n)
 
    // Compute u = c^λ mod n²
    u := new(big.Int).Exp(ciphertext, lambda, nSquare)
 
    // Compute L(u) = (u - 1) / n
    u.Sub(u, big.NewInt(1))
    u.Div(u, n)
 
    // Multiply by μ and mod n
    plainText := new(big.Int).Mul(u, mu)
    plainText.Mod(plainText, n)
 
    return plainText
}
 
// Ordered should be invoked sequentially as messages are ordered
//
// messageBatches length: 0, pending: false
//   - impossible, as we have just received a message
//
// messageBatches length: 0, pending: true
//   - no batch is cut and there are messages pending
//
// messageBatches length: 1, pending: false
//   - the message count reaches BatchSize.MaxMessageCount
//
// messageBatches length: 1, pending: true
//   - the current message will cause the pending batch size in bytes to exceed BatchSize.PreferredMaxBytes.
//
// messageBatches length: 2, pending: false
//   - the current message size in bytes exceeds BatchSize.PreferredMaxBytes, therefore isolated in its own batch.
//
// messageBatches length: 2, pending: true
//   - impossible
//
// Note that messageBatches can not be greater than 2.
func (r *receiver) Ordered(msg *cb.Envelope) (messageBatches [][]*cb.Envelope, pending bool) {
 
    
    payload := &cb.Payload{}
    if err := proto.Unmarshal(msg.Payload, payload); err != nil {
        logger.Errorf("Failed to unmarshal payload: %v", err)
    } else {
        tx := &pb.Transaction{}
        if err := proto.Unmarshal(payload.Data, tx); err != nil {
            logger.Errorf("Failed to unmarshal transaction: %v", err)
        } else {
            for _, action := range tx.Actions {
                cap := &pb.ChaincodeActionPayload{}
                if err := proto.Unmarshal(action.Payload, cap); err != nil {
                    logger.Errorf("Failed to unmarshal chaincode action payload: %v", err)
                } else {
                    proposalResponsePayload := &pb.ProposalResponsePayload{}
                    if err := proto.Unmarshal(cap.Action.ProposalResponsePayload, proposalResponsePayload); err != nil {
                        logger.Errorf("Failed to unmarshal proposal response payload: %v", err)
                    } else {
                        chaincodeAction := &pb.ChaincodeAction{}
                        if err := proto.Unmarshal(proposalResponsePayload.Extension, chaincodeAction); err != nil {
                            logger.Errorf("Failed to unmarshal chaincode action: %v", err)
                        } else {
                            logger.Infof("Endorsement response payload: %s", string(chaincodeAction.Response.Payload))
                            endorsementPayload := chaincodeAction.Response.Payload
 
                                if json.Valid(endorsementPayload) {
                                    var endorsementData map[string]interface{}
                                    err := json.Unmarshal(endorsementPayload, &endorsementData)
                                    if err != nil {
                                        logger.Errorf("Failed to extract responses field: %s", err)
                                        return nil, false
                                    }
                        
                                    // Extract "Responses" field
                                    if assetData, ok := endorsementData["asset"].(map[string]interface{}); ok {
                                        if responses, found := assetData["Responses"].(string); found {
                                            logger.Infof("Extracted Responses: %s", responses)
 
                                            n := new(big.Int)
                                            lambda := new(big.Int)
                                            mu := new(big.Int)
                                            n.SetString("30728744964821944482906991141350135883036977729841200921163471038417086370597331113352010483802494021478453749511314339371037515930484467686542587934927631376348719402746324882955532738005800671704156348311228031066874124256909005581643686595333923555272861530013748292776101178003615899225025001180586212875128736798913164255883887370520580671232782738547428258490741802098578634790950490328101305911680963472116368871804898986387165271849124946116262623804588376080380463804665212619882236903226911291895278243928695715739353705339556203802340690142292093161445357766207365243242008258238091693488590245544044788803",10)
                                            lambda.SetString("15364372482410972241453495570675067941518488864920600460581735519208543185298665556676005241901247010739226874755657169685518757965242233843271293967463815688174359701373162441477766369002900335852078174155614015533437062128454502790821843297666961777636430765006874146388050589001807949612512500590293106437389058000722937264582966244399722358813102082325645926289194123044486889374686159091217426202619582844236308949432779272628173379376152569844067970169923602558999795108906648819874361476069391365044378938423019301899196930706181861105692897130562057320331033630466207006582824646019474353900260734829107307964",10)
                                            mu.SetString("13256689890341387695013929131131765654283999493225857599058548853923222925438609447537396204587441477946298850366282115233762302190134686302488316151532609729698299282353491182653414420059437681837256170581426343070151322441473389717381960865097160349179315339913469141186286033210897195621761033308960576750016804447796083447578743290865653399347771811166205874014066902099419524266484336769485324728980724879834258719168220528184493826567184894000679291822741747364698453997973516297778974799747207359538014640936543334396047551461656727225723215628510130983193394355895077928074692909962851883150494273332640093320",10)
                                            q := big.NewInt(18)
                                            p3 := big.NewInt(2602)
                                            p2 := big.NewInt(250081)
                                            p1 := big.NewInt(1263066)
 
                                            voteStrings := strings.Split(responses, "|")
 
                                            product := big.NewInt(1) // Start with 1 for multiplication
                                            for _, hexVote := range voteStrings {
                                                voteBigInt := new(big.Int)
                                                voteBigInt.SetString(hexVote, 16) // Convert hex to big.Int
 
                                                // Multiply all votes together
                                                product.Mul(product, voteBigInt)
                                            }
 
                                            decryptedVote := DecryptPaillier(product, lambda, mu, n)
                                            
                                            k1 := new(big.Int).Div(decryptedVote, p1)   // k1 = total / p3
                                            decryptedVote.Mod(decryptedVote, p1)                // total = total % p3
 
                                            k2 := new(big.Int).Div(decryptedVote, p2)   // k2 = total / p2
                                            decryptedVote.Mod(decryptedVote, p2)                // total = total % p2
 
                                            k3 := new(big.Int).Div(decryptedVote, p3)   // k3 = total / p1
                                            decryptedVote.Mod(decryptedVote, p3)                // total = total % p1
 
                                            Non := new(big.Int).Div(decryptedVote, q)   // Non = total / q
                                            decryptedVote.Mod(decryptedVote, q)        
 
                                            logger.Infof("k1:: %d, k2: %d, k3: %d, Non: %d", k1, k2, k3, Non)
 
                                            if k1.Cmp(big.NewInt(1)) == 1 { // k1 > 1
                                                logger.Infof("Selected")
                                            } else if k2.Cmp(big.NewInt(1)) == 1 { // k2 > 1
                                                logger.Infof("Selected")
                                            } else if k3.Cmp(big.NewInt(2)) == 1 { // k3 > 2
                                                logger.Infof("Selected")
                                            } else {
                                                logger.Infof("Rejected")
                                                return [][]*cb.Envelope{}, false
                                            }
 
                                            
                                        }
                                    }
                                }
                        }
                    }
                }
            }
        }
    }
 
 
    if len(r.pendingBatch) == 0 {
        // We are beginning a new batch, mark the time
        r.PendingBatchStartTime = time.Now()
    }
 
    ordererConfig, ok := r.sharedConfigFetcher.OrdererConfig()
    if !ok {
        logger.Panicf("Could not retrieve orderer config to query batch parameters, block cutting is not possible")
    }
 
    batchSize := ordererConfig.BatchSize()
 
    messageSizeBytes := messageSizeBytes(msg)
    if messageSizeBytes > batchSize.PreferredMaxBytes {
        logger.Debugf("The current message, with %v bytes, is larger than the preferred batch size of %v bytes and will be isolated.", messageSizeBytes, batchSize.PreferredMaxBytes)
 
        // cut pending batch, if it has any messages
        if len(r.pendingBatch) > 0 {
            messageBatch := r.Cut()
            messageBatches = append(messageBatches, messageBatch)
        }
 
        // create new batch with single message
        messageBatches = append(messageBatches, []*cb.Envelope{msg})
 
        // Record that this batch took no time to fill
        r.Metrics.BlockFillDuration.With("channel", r.ChannelID).Observe(0)
 
        return
    }
 
    messageWillOverflowBatchSizeBytes := r.pendingBatchSizeBytes+messageSizeBytes > batchSize.PreferredMaxBytes
 
    if messageWillOverflowBatchSizeBytes {
        logger.Debugf("The current message, with %v bytes, will overflow the pending batch of %v bytes.", messageSizeBytes, r.pendingBatchSizeBytes)
        logger.Debugf("Pending batch would overflow if current message is added, cutting batch now.")
        messageBatch := r.Cut()
        r.PendingBatchStartTime = time.Now()
        messageBatches = append(messageBatches, messageBatch)
    }
 
    logger.Debugf("Enqueuing message into batch")
    r.pendingBatch = append(r.pendingBatch, msg)
    r.pendingBatchSizeBytes += messageSizeBytes
    pending = true
 
    if uint32(len(r.pendingBatch)) >= batchSize.MaxMessageCount {
        logger.Debugf("Batch size met, cutting batch")
        messageBatch := r.Cut()
        messageBatches = append(messageBatches, messageBatch)
        pending = false
    }
 
    return
}
 
// Cut returns the current batch and starts a new one
func (r *receiver) Cut() []*cb.Envelope {
    if r.pendingBatch != nil {
        r.Metrics.BlockFillDuration.With("channel", r.ChannelID).Observe(time.Since(r.PendingBatchStartTime).Seconds())
    }
    r.PendingBatchStartTime = time.Time{}
    batch := r.pendingBatch
    r.pendingBatch = nil
    r.pendingBatchSizeBytes = 0
    return batch
}
 
func messageSizeBytes(message *cb.Envelope) uint32 {
    return uint32(len(message.Payload) + len(message.Signature))
}