## <font color=#ff0000>**Agents**</font>
>所有代理人都可以通过学习来提高他们的性能。

- <font color=#00ffff>**Reactive Agent**</font>
  > Perception -> Action
  - 仅根据目前感知到的情况选择下一步行动
  - 使用一个 "政策 "或一套简单的应用规则
  - 没有记忆或 "状态"
  - 不能根据以前的观察做出决定
  - 可能重复相同的行动序列
- <font color=#00ffff>**Model-Based Agent**</font>
  > Perception -> World Model -> Action
  - 通过保持对它现在看不到的那部分世界的跟踪来处理部分可观察性。
  - 一个有世界模型但没有计划的代理人可以看到过去，但不能看到未来。
- <font color=#00ffff>**Planning Agent**</font>
  > Perception -> World Model -> Planning -> Action
  - 涉及对未来的考虑
  - "如果我做这样那样的事，会发生什么？"以及 "这样做会让我高兴吗？"
  - 采取行动以实现其目标
- <font color=#00ffff>**Utility-based agent**</font>
  - 基于世界的模型、基于效用的代理使用
  - 衡量世界各种状态的偏好的效用函数
  - 选择导致最佳预期效用的行动
  - 试图使预期的 "happiness "最大化。
  - 预期效用是通过对所有可能的结果状态取平均值来计算的。
  - 按结果的概率进行加权。
- <font color=#00ffff>**Game Playing Agent**</font>
  > Perception -> World Model <-> Opponent Model -> Planning -> Action
- <font color=#00ffff>**Learning Agent**</font>
  > Perception -> Critic -> Performance element -> Learning element -> Problem generator -> Action
  - PE 接受观念；决定行动
  - Critic 对绩效要素的表现给予反馈
  - LE 使用反馈来决定如何修改性能元素以在未来做得更好。
  - PG 创造新的任务，以提供新的和丰富的经验。

## <font color=#ff0000>**Uninformed Search**</font>
> 不使用特定问题的信息--无信息（或 "盲目"）的搜索策略只使用问题定义中的信息（只能区分目标和非目标状态）。
>
> 不断搜索，直到找到目标
>
> No domain knowledge

- <font color=#00ffff>**Breadth First Search**</font>
  > **Complete:** Yes
  >
  > **Time: O(b^d)**
  >
  > **Space: O(b^d)**
  >
  > **Optimal:** 是的，但只有在所有行动都有相同成本的情况下
  - 需要一个新的数据结构来表示已探索状态的集合
  - 首先找到最浅的目标
  - 空间是BFS的大问题。它随着深度的增加而呈指数级增长

- <font color=#00ffff>**Depth First Search**</font>
  > **Complete:** No
  >
  > **Time: O(b^m)**, m = maximum depth of search tree
  >
  > **Space: O(bm)**
  >
  > **Optimal:** No, can find suboptimal solutions first.
  - 对于有深度或无限路径的问题，要避免深度优先搜索

- <font color=#00ffff>**Uniform Cost Search**</font>
  > **Complete:** Yes
  >
  > **Time:** O(b^[C*/ϵ]), C* = cost of the optimal solution every transition costs at least ϵ
  >
  > **Space:** O(b^[C*/ϵ]), b^[C*/ϵ] = b^d if all step costs are equal
  >
  > **Optimal:** Yes

  - "Lowest-cost-first Search"
  - 用优先级队列实现
  - 这种算法是先展开成本最低的未展开的节点，当所有路径的成本都相同时，就是正常的广度优先搜索。而且它详尽地扩展所有比目标更接近初始状态的节点。所以时间效率不会很高，内存消耗也非常快。

- <font color=#00ffff>**Depth Limited Search**</font>
  > **Complete:** Yes
  >
  > **Time:** O(b^k), where k is the depth limit
  >
  > **Space:** O(bk)
  >
  > **Optimal:** No, can find suboptimal solutions first.
  - "Depth Bounded Search"
  - 很难决定深度边界


- <font color=#00ffff>**Iterative Deepening Search**</font>
  > **Complete:** Yes
  >
  > **Time:** O(b^d)
  >
  > **Space:** O(bd)
  >
  > **Optimal:** Yes, if step costs are identical. 
  - 结合了深度优先和广度优先搜索的优点
  - 进行一系列深度有限的深度优先搜索，深度为1、2、3，等等。
  - 早期的状态将被多次扩展，但这可能没有太大关系
因为大部分的节点都在叶子附近。
  - 一般来说，对于不知道解的深度的大搜索空间，迭代深化是首选的搜索策略。
  - 这种算法使用深度优先搜索来递归地寻找一个解决方案，直到指定的深度限制（D）。时间效率可能很差，特别是当目标的位置与算法开始时选择的位置相反时，例如，从树的最左边的节点开始，然而答案却在树的最右边的底部节点。这相当于扩展所有可能的节点。然而，内存效率并不差，线性空间与DFS相似。
- <font color=#00ffff>**Bidirectional Search**</font>
  > **Time:** O(bd/2)
  - "双向搜索"
  - 既从初始状态向前搜索，又从目标向后搜索
  - 当这两个搜索在中间相遇时停止。
  - 需要有效的方法来检查新节点是否出现在另一半搜索中。
  - 复杂度分析假定这可以在恒定时间内使用哈希表完成。
  


## <font color=#ff0000>**Informed search**</font>
> 使用启发式方法来提高效率, 比无信息的搜索更有效地利用特定问题的知识
> 
> 朝着对目标的最佳猜测方向搜索
> 
> Uses domain knowledge
- <font color=#00ffff>**Best-first search**</font>
  - 最佳优先搜索使用一个评价函数 f() 对队列中的节点进行排序
  - 类似于统一成本搜索

- <font color=#00ffff>**Greedy best-first search**</font>
  >  **Complete:** No. Can get stuck in loops.
  >
  > **Time:** O(b^m), where m is the maximum depth in search space
  >
  > **Space:** O(b^m)
  >
  > **Optimal:** No
  - f(n) = h(n), h(n) = 0 if is a goal state
  - 始终根据启发式函数选择最接近目标的节点
  - Like depth-first search, except pick next node by h(n)
  - 贪婪搜索与深度优先搜索有同样的缺陷。
  - 然而，一个好的启发式方法可以大大减少时间和内存成本。
  
- <font color=#00ffff>**A*** **search**</font>
  >  **Complete:** Yes
  >
  > **Time:** Exponential
  >
  > **Space:** Keeps all expanded nodes is memory
  >
  > **Optimal:** Yes (assuming is admissible)
  - f(n) = g(n) + h(n), g(n) = cost of path from start to n
  - 结合了统一成本搜索和贪婪搜索
    - Greedy Search minimises h(n)
      - efficient but not optimal or complete
    - Uniform Cost Search minimises g(n)
      - optimal and complete but not efficient
  - 这种算法结合了贪婪搜索和统一成本搜索的优点，所以时间效率非常高。但是，他将所有的节点保留在内存中，所以内存效率不高。当深度过大时，很容易导致
内存溢出

- <font color=#00ffff>**Iterative Deepening A*** **Search**</font>
  - 这个算法是A的一个低内存变体，它首先执行一系列深度优先搜索。然后，当总和f()超过某个预先定义的阈值时，就会切断每次搜索。因此，它具有很高的时间效率和内存效率

- <font color=#00ffff>**f() = (2-w)\*g()+ w\*h()**</font>
  - 我们从讲座中得知，当w=0时，是统一成本搜索，而当w=1时，是IDA*，当w=2时，是贪婪搜索。
此外，IDA*中的统一成本搜索算法的权重占到了其总权重的一半。始终考虑从起点到当前节点的成本，所以保证了它是最优解。但是速度会慢很多，因为它要展开更多的节点。
  - 在贪婪算法中，唯一的权重是启发式函数。也就是说，它关注的是当前节点到目标的成本。因此，虽然可以快速找到目标，但不能保证路径的长度是最优的。
  - 因此，当我们把IDA*中影响g()和h()的W的权重从1.2一点一点地改变到1.6时，我们可以从结果中清楚地看到，路径的长度慢慢变大，扩展的总状态数逐渐减少。


## <font color=#ff0000>**Constraint Satisfaction**</font>
- <font color=#00ffff>**约束满足问题(CSPs)**</font>
  - 约束满足问题是由一组变量Xi定义的，每个变量都有一个可能的值域Di，以及一组规定了可允许的值组合的约束C。
  - 其目的是要从域Di中找到一个变量Xi的分配，使其不违反任何约束条件C。
  - Example: Map-Colouring, n-Queens Puzzle, Cryptarithmetic
  - 路径搜索问题和CSP之间的区别
    - 路径搜索问题（例如：送货机器人）
      - 知道最终状态很容易
      - 困难的部分是如何到达那里
    - 约束满足问题（如n-Queens）。
      - 困难的部分是知道最终的状态
      - 如何到达那里很容易


- <font color=#00ffff>**Backtracking search and heuristics**</font>
  - 逆向搜索; CSP可以通过给变量逐一赋值，以不同的组合来解决。
  - 每当一个约束条件被违反时，就回到最近分配的变量，给它分配一个新的值。
  - Minimum Remaining Values
    - 最小剩余值(MRV)
    - 选择合法剩余值最少的变量
    - 最受约束的变量
  - Degree Heuristic
    - 度启发式。
    - 选择对变量有最多约束的变量 (即图中最多的边)
    - 如果程度相同，选择任何一个
    程度启发法
  - Least Constraining Value
    - 最小约束值
    - 给定一个变量，选择限制性最小的值。在其余的变量中排除最少的值。
    - 更一般地说，3个允许的值会比2个好，等等。

- <font color=#00ffff>**Forward checking and arc consistency**</font>
  - 前向检查可以防止保证以后失败的分配
  - 追踪未分配变量的剩余合法值
  - 当任何变量没有合法值时，终止搜索
  - 修剪掉搜索树的那一部分，并进行回溯。
  - Arc Consistency
    - 弧形的连贯性
    - X → Y is consistent if for every value x of X there is some allowed y
    - 弧形一致性比前向检查更早地检测到故障。
    - 对于某些问题，它可以极大地加快搜索速度。
    - 对于其他问题，由于计算开销的原因，它可能会减慢搜索速度。

- <font color=#00ffff>**Variable elimination**</font>
  - 消除变量，一个一个地消除
  - 用相邻变量的约束来代替它们


- <font color=#00ffff>**Local search**</font>
  - 还有一类用于解决CSP的算法，叫做"Iterative Improvement"或 "Local Search"。
  - **爬坡法 Hill climbing**
    - 变量选择：随机选择任何有冲突的变量
    - 通过最小冲突启发式选择值
    - 选择违反最小约束的值
  - **模拟退火 Simulated annealing**
    - 模拟退火法可以帮助摆脱局部最优状态
    - 基于前一状态(h0)和新状态(h1)之间的评价差异的随机爬坡法。
    - 前状态（h0）和新状态（h1）之间的差异。
    - 如果h1<h0，就一定要做出改变（越小越好）。
    - 否则，按概率做出改变
    其中T是一个 "温度 "参数。
    - 当T→0时，降低为普通的爬坡法
    - 当T → ∞时，成为完全的随机搜索
    - 有时，我们在搜索过程中逐渐减少T的值

## <font color=#ff0000>**Reinforcement Learning**</font>
> 强化学习试图找到在不确定和非决定性的环境中采取行动的最佳方式。
>
> 每次行动后都会得到奖励, 更新其策略, 继续努力使其奖励最大化
- <font color=#00ffff>**Types of Learning**</font>
  - Supervised Learning 监督学习
    - 代理人被赋予输入/输出对的例子
    - 学习一个从输入到输出的函数，该函数与训练实例一致，并且
    归纳到新的例子上
  - Unsupervised Learning 无监督学习
    - 代理人只得到输入
    - 试图在这些输入中找到结构
  - Reinforcement Learning 强化学习
    - 每次提出一个训练实例
    - 必须根据奖励来猜测最佳输出，试图使（预期）奖励最大化。
- <font color=#00ffff>**Types of Environment**</font>
  - 被动的和决定性的
  - 被动的和随机的
  - 主动和决定性的（国际象棋）
  - 主动和随机的（双陆棋，机器人）。

- <font color=#00ffff>**State Transition Graph**</font>
  - 每个节点都是一个状态
  - 行动导致从一个状态到另一个状态的转换
  - 策略是一组过渡规则
  - 即在一个给定的状态下采取何种行动
  - 代理人在每次行动后都会收到奖励
  - 行动可能是非决定性的
  - 相同的行动不一定会产生相同的状态

- <font color=#00ffff>**Reinforcement Learning Framework**</font>
  - 一个代理与它的环境进行互动。
  - 有一组状态，S ，和一组行动，A
  - 在每个时间步骤t中，代理处于状态st
  - 它必须选择一个行动，将状态改变为s<sub>t+1</sub> = δ(s<sub>t</sub>, a<sub>t</sub>) and receives reward r(s<sub>t</sub>, a<sub>t</sub>)
    - 世界是非决定性的，即一个行动可能并不总是把系统带到相同的状态
    - 因此 δ and r 可以是多值的，有一个随机元素
  - 目的是找到一个最优的政策π : S → A，使其达到最大的累积奖励。


- <font color=#00ffff>**Markov Decision Process（MDP）**</font>
  - 马尔科夫决策过程
  - 假设当前状态拥有决定采取何种行动所需的所有信息
  - 假设行动有一个固定的期限
  - 代理人最初只知道可能的状态集和可能的行动集。
  - 动量，和奖励函数，都没有给代理人。
  - 每次行动后，代理观察它所处的状态，并获得奖励。

- <font color=#00ffff>**Q Value**</font>
  - Q(s, a) = r(s, a) + γV*(s′)
  - 一个行动（a）在一个状态（s）中的Q值是该行动的即时回报加上该行动后遵循最优政策的折现值
  - V*是遵循最优政策得到的价值
  - s′= δ(s, a)是假设最优政策下的后续状态

## <font color=#ff0000>**Planning**</font>
> 规划是根据代理人的能力、目标和世界的状态来找到一个行动序列来解决一个目标
>
> 假设:
>> 世界是决定性的。
>> 没有超出机器人控制范围的外生事件改变世界的状态。
>> 代理人知道它处于什么状态。
>
>> 时间从一个状态到下一个状态的进展是不连续的。
>
>> 目标是需要实现或维持的状态的谓词。

- <font color=#00ffff>**关于行动的推理**</font>
  - 规划代理或基于目标的代理比反应性代理更灵活
  因为支持其决策的知识是明确表示的
  并且可以被修改。
  - 代理的行为可以很容易地被改变。
  - 当假设被违反时不工作
  - 由于行动的执行，环境发生变化
  - 规划场景:
    - 代理人可以控制其环境
    - 只有原子行动，而不是有持续时间的过程
    - 环境中只有单一的代理（无干扰）。
    - 只有由于代理人执行行动而产生的变化（没有进化）。
  - 更复杂的例子:
    - 机器人杯足球赛
    - 送货机器人
    - 自动驾驶汽车
- <font color=#00ffff>**STRIPS 规划器**</font>
  - STRIPS = 斯坦福研究所问题解决器
  - 大多数规划者使用 "类似STRIPS的表示法", 即带有一些扩展的STRIPS
  - STRIPS做了一些简化:
    - 目标中没有变量
    - 只给出积极的关系
    - 未提及的关系被认为是假的（C.W.A.--封闭世界的假设）。
    - 效果是关系的联结
  - 每个行动都有一个:
    - precondition，指定何时可以执行该动作。
    - effect, 一组对原始特征的赋值，该赋值被此动作变为真。
    行动使之成为真的一组赋值。
    - 通常被分割成一个ADD列表（行动后变成真的东西）
    - 和删除列表（行动后变成假的东西）。
    - 假设：效果中未提及的每个基元特征都不受动作的影响。
  - Example: 
    - Pick-up coffee (puc):
      - precondition: [cs, ¬rhc]
      - effect: [rhc]
    - Deliver coffee (dc):
      - precondition: [off, rhc]
      - effect: [¬rhc, ¬swc]

- <font color=#00ffff>**Forward 前进规划**</font>
  - 节点是世界上的状态
  - 弧线对应于将一种状态转化为另一种状态的行动
  - 开始节点是初始状态
  - 如果目标条件得到满足，搜索就成功结束。
  - 一个路径对应于实现目标的计划
  - 前瞻性规划者现在是最好的之一。
  - 使用启发式方法来估计成本
  - 有可能使用启发式搜索，如A*，以减少搜索量

- <font color=#00ffff>**Regression 回归规划**</font>
  - (Backward Search)
  - 节点是子目标。
  - 弧对应于行动。一个从节点g到g′的弧，标有行动act。means:
    - act是在实现子目标g之前进行的最后一个动作，并且
    - 节点g′是一个子目标，它必须在行动之前为真，以便g在行动之后为真。
 
  - 开始节点是要实现的规划目标。
  - 搜索的目标条件，goal(g)，如果g在初始状态为真，则为真。

- <font color=#00ffff>**图形规划**</font>
  - 使用约束解法来实现更好的启发式估计
  - 只适用于命题性问题
  - 像CSP中的一致性检查
    - 预处理约束条件以创建一个规划图
    - 规划图限制了可能的状态和行动
  - 规划图不是一个计划
    - 它制约着可能的计划的范围

## <font color=#ff0000>**Supervised Learning**</font>
- 给定一个训练集和一个测试集
  - 每一个都有一组例子
  - 例子有属性和一个类别，或目标值
- 代理人给定训练集中每个例子的属性和类别
  - 尝试预测测试集中每个例子的类别
- 许多有监督的学习方法，例如。
  - 决策树
  - 神经网络
  - 支持向量机，等等。
- Methodology
  1. "特征工程" - 选择相关的特征
  2. 选择输入特征和输出的表示方法
  3. 预处理，从原始数据中提取特征
  4. 选择要评估的学习方法
  5. 选择训练机制（包括参数）。
  6. 评估
     1. 选择用于比较的基线
     2. 选择内部验证的类型，如交叉验证
     3. 用人的专业知识和其他基准来检查结果的真实性
- 监督学习 Issues
  - Framework（决策树、神经网络、SVM等）
  - representation（输入和输出的）。
  - 预处理/后处理
  - 训练方法（感知器、反向传播等）。
  - generalisation 泛化（避免过度拟合）
  - evaluation 评估（单独的训练和测试集）
  
- <font color=#00ffff>**Information Gain**</font>
  - 信息增益是基于信息论的概念，即熵。
  在信息论中，香农熵或信息熵是对与随机变量相关的不确定性的一种衡量。
  - 它量化了信息中包含的信息，通常以比特或
  位/符号。
  - 它是传播信息所需的最小信息长度。

- <font color=#00ffff>**Entropy**</font>
  - 熵是衡量我们获得多少信息的一种方法，当类值
  揭示给我们的信息量。
  - 在决策树学习中，当我们按某一特定属性对数据集进行分割时
  产生的熵就会降低。
  - 熵为0意味着所有的例子都有相同的类值
  - 熵为1意味着它们是随机分布的。
  - 如果n个类值的先验概率是p1, ...... , pn，那么熵就是
    - 𝐻(⟨𝑝1,…, 𝑝𝑛,⟩) =Σ<sub>𝑛=1</sub> −𝑝<sub>𝑖</sub> log<sub>2</sub> 𝑝<sub>i</sub>
- <font color=#00ffff>**Entropy and Huffmann Coding**</font>
  - 熵和赫夫曼编码
  - 熵是指通过一个（块）哈夫曼编码方案实现的每个符号的比特数。
  - 假设我们想把一个由A和B两个字母组成的长信息编码成一个比特串，这两个字母出现的频率相同。
  由两个字母A和B组成，它们出现的频率相同。
  - 可以通过分配A=0，B=1来完成。
  - 也就是说，每个字母需要一个比特（二进制数字）来编码。
  - 例1：𝐻(⟨0.5, 0.5 ⟩) = 1比特

- <font color=#00ffff>**Decision Trees**</font>
  - 决策树学习是一种逼近离散值目标函数的方法，其中学习的函数由决策树表示。
  - 决策树也可以用if-then-else规则表示。
  - 决策树学习是最广泛使用的归纳推理方法之一
  - 决策树学习在决策树的空间中进行启发式搜索
  - 停在最小的可接受的树上
  - 奥卡姆剃刀：简单性和准确性之间的权衡
  - 通过建立更小的树来提高概括性（使用熵）。
  - 根据拉普拉斯误差修剪节点
  - 修剪决策树的其他方法



