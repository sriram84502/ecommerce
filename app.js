const express = require('express'); // Import express
const ejs = require('ejs'); // Import ejs
const bodyParser = require('body-parser');
const path = require('path'); // Import path
const mongoose = require('mongoose');
const session = require('express-session');
const mongodbSession = require('connect-mongodb-session')(session);
const methodOverride = require('method-override');
const Razorpay = require('razorpay');
require('dotenv').config();

const app = express(); // Initialize express app
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs'); // Set EJS as the view engine
app.use(bodyParser.urlencoded({ extended: true }));
app.use(methodOverride('_method'));
const razorpay = new Razorpay({
    key_id: process.env.RAZOR_PAY_ID_KEY,
    key_secret: process.env.RAZOR_PAY_SECRET_KEY,
});


const isAuth = (req, res, next) => {
    if (req.session.isLoggedIn) {
        next();
    } else {
        res.redirect('/login');
    }
}

const isAlreadyLoggedIn = (req, res, next) => {
    if (req.session.isLoggedIn) {
        res.redirect("/");
    } else {
        next();
    }
}

const isAdmin = (req, res, next) => {
    if (req.session.isAdmins == false) {
        res.redirect("/");
    } else {
        next();
    }
}

//DB CONNECT
mongoose.connect('mongodb+srv://admin:sai4502@cluster0.w7k9cg0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0').then(() => {
    console.log('Connected');
});

///SCHEMAS
const productSchema = new mongoose.Schema({
    name: { type: String },
    description: { type: String },
    price: { type: Number },
    stock: { type: Number },
    veg: { type: Boolean },
    rating: { type: Number },
    category: { type: String },
    imageUrl: { type: String },
    ispopular: { type: Boolean },
    isseller: { type: Boolean }
});

const categoriesSchema = new mongoose.Schema({
    category: { type: String },
    image: { type: String }
});

const cartItemSchema = new mongoose.Schema({
    productId: { type: mongoose.Schema.Types.ObjectId,ref: 'Product'  },
    quantity: { type: Number, required: true },
});

const userSchema = new mongoose.Schema({
    name: { type: String },
    email: { type: String, unique: true },
    password: { type: String },
    role: { type: Number },
    cart: [cartItemSchema]
});

const orderSchema = new mongoose.Schema({
    product: cartItemSchema,
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { type: String },
    address: { type: String },
    transactionId: { type: String }
});

const sessionLogSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User'},
    loginTime: { type: Date, default: Date.now },
    logoutTime: { type: Date },
    ipAddress: { type: String }
});

const SessionLog = mongoose.model('SessionLog', sessionLogSchema);

const Product = mongoose.model('Product', productSchema);
const User = mongoose.model('User', userSchema);
const Categories = mongoose.model('Categories', categoriesSchema);
const Orders = mongoose.model('Orders', orderSchema);

//Sessions
const store = new mongodbSession({
    uri: "mongodb+srv://admin:sai4502@cluster0.w7k9cg0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0",
    collection: 'session'
});
app.use(session({
    secret: "this is secret key",
    resave: false,
    saveUninitialized: false,
    store: store
}));

// Define a route for the root URL
app.get('/', isAuth, async (req, res) => {
    const categories = await Categories.find()
    const products = await Product.find()
    const user = await User.findById(req.session.user._id).populate('cart.productId');
    res.render("index", { categories:categories,products:products,user:user });
});

app.get('/products', isAuth, async (req, res) => {
    let products = await Product.find()
    const user = await User.findById(req.session.user._id).populate('cart.productId');
    res.render("products",{products:products,user:user});
});
app.put('/getproducts', isAuth, async (req, res) => {
    let products = await Product.find({category:req.body.cat})
    res.render("products",{products:products});
});

app.put('/product', isAuth, async (req, res) => {
    const product = await Product.findById(req.body.productId);
    const products = await Product.find()
    const user = await User.findById(req.session.user._id).populate('cart.productId');
    res.render("product", { product: product,products:products,user:user });
});

app.get('/cart', isAuth, async (req, res) => {
    const user = await User.findById(req.session.user._id).populate('cart.productId');
    res.render("cart",{user:user});
});

app.get('/orders', isAuth, async (req, res) => {
    const orders = await Orders.find({ user: req.session.user._id })
            .populate('user')
            .populate('product.productId');

    const user = await User.findById(req.session.user).populate('cart.productId');
    res.render("order",{orders:orders,user:user});
});

app.put('/cart', isAuth, async (req, res) => {
    try {
        const product = await Product.findById(req.body.productId);
        if (!product) {
            return res.status(404).send("Product not found");
        }

        const user = await User.findById(req.session.user._id); // Fetch user from database
        if (!user) {
            return res.status(404).send("User not found");
        }

        const cartItem = {
            productId: product._id,
            quantity: req.body.quantity || 1, // Default to 1 if not provided
        };

        user.cart.push(cartItem);

        await user.save(); // Save the updated user document

        res.redirect("/");
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.delete('/cart/:productId', isAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.user._id);
        if (!user) {
            return res.status(404).send("User not found");
        }

        user.cart = user.cart.filter(item => item.productId.toString() !== req.params.productId);
        await user.save();
        
        res.redirect('/cart'); // Redirect to the cart page after removal
    } catch (error) {
        res.status(500).send(error.message);
    }
});


app.put('/cartp', isAuth, async (req, res) => {
    try {
        const product = await Product.findById(req.body.productId);
        if (!product) {
            return res.status(404).send("Product not found");
        }
        console.log(product);
        const user = await User.findById(req.session.user._id); // Fetch user from database
        if (!user) {
            return res.status(404).send("User not found");
        }
        console.log(user);
        const existingCartItem = user.cart.find(item => item.productId.toString() === product._id.toString());

        if (existingCartItem) {
            existingCartItem.quantity += parseInt(req.body.quantity) || 1; // Increase the quantity
        } else {
            const cartItem = {
                productId: req.body.productId,
                quantity: parseInt(req.body.quantity) || 1, // Default to 1 if not provided
            };

            user.cart.push(cartItem);
        }
        console.log(user);
        await user.save(); // Save the updated user document

        res.redirect("/products");
    } catch (error) {
        res.status(500).send(error.message);
    }
});

app.get('/checkout', isAuth, async (req, res) => {
    const user = await User.findById(req.session.user._id).populate('cart.productId');
    res.render("checkout",{user:user});
});

app.post('/create-order', isAuth, async (req, res) => {
    const user = await User.findById(req.session.user._id).populate('cart.productId');
    if (!user || user.cart.length === 0) {
        return res.status(400).send("Cart is empty");
    }

    let totalAmount = 20; // Base amount for any additional charges
    user.cart.forEach(item => {
        totalAmount += item.productId.price * item.quantity;
    });

    const options = {
        amount: (totalAmount * 100), // amount in the smallest currency unit
        currency: "INR",
        receipt: `order_rcptid_${Date.now()}`,
    };

    try {
        const order = await razorpay.orders.create(options);
        res.json(order); // Send the order details to the client

        // Proceed with creating individual orders for each product in the cart
        for (let i = 0; i < user.cart.length; i++) {
            const product = {
                productId: user.cart[i].productId._id,
                quantity: user.cart[i].quantity,
            };
            const newOrder = new Orders({
                address: "", // Add address logic here if needed
                product: product,
                status: "pending",
                transactionId: order.receipt,
                user: req.session.user._id,
            });
            await newOrder.save();
        }

        // Clear the user's cart
        user.cart = [];
        await user.save();
    } catch (error) {
        console.error(error);
    }
});


app.post('/verify-payment', isAuth, async (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    const shasum = crypto.createHmac('sha256', process.env.RAZOR_PAY_SECRET_KEY);
    shasum.update(`${razorpay_order_id}|${razorpay_payment_id}`);
    const digest = shasum.digest('hex');

    if (digest === razorpay_signature) {
            res.redirect('/checkout')
    } else {
        res.status(400).send("Payment verification failed");
    }
});

app.get('/admin', isAdmin, async (req, res) => {
    const users = await User.find({ role: 1 });
    const products = await Product.find();
    const categories = await Categories.find();
    const orders = await Orders.find();
    res.render("admin", { users: users, products: products, categories: categories, orders: orders });
});

app.get('/admin/sessions', isAdmin, async (req, res) => {
    const users = await User.find({ role: 1 });
    const sessions = await SessionLog.find().populate('userId');
    res.render("manage-users", { users: users, sessions: sessions });
});

app.get('/admin/delete-user/:id', isAdmin, async (req, res) => {
    await SessionLog.deleteMany({ userId: req.params.id });
    await User.findByIdAndDelete(req.params.id);
    res.redirect('/admin/manage-users');
});

app.get('/admin/categories', isAdmin, async (req, res) => {
    const categories = await Categories.find();
    res.render('categories', { categories: categories });
});

app.post('/admin/categories', isAdmin, async (req, res) => {
    const category = new Categories({
        category: req.body.category,
        image: req.body.image
    });
    await category.save();
    const categories = await Categories.find();
    res.render('categories', { categories: categories });
});

app.get('/delete-category/:id', isAdmin, async (req, res) => {
    await Categories.findByIdAndDelete(req.params.id);
    res.redirect('/admin/categories');
});

app.get('/admin/products', isAdmin, async (req, res) => {
    const products = await Product.find();
    const categories = await Categories.find();
    res.render('addproducts', { products: products,categories:categories });
});

app.post('/admin/products', isAdmin, async (req, res) => {
    const product = new Product({
        category: req.body.category,
        name: req.body.product,
        description: req.body.description,
        imageUrl: req.body.image,
        price: req.body.price,
        rating: req.body.rating,
        stock: req.body.stock,
        veg: req.body.veg
    })
    await product.save()
    res.redirect('/admin/products');
});

app.delete('/admin/products/:id', isAdmin, async (req, res) => {
    await Product.findByIdAndDelete(req.params.id);
    res.redirect('/admin/products');
});

app.put('/admin/products/:id',isAdmin,async (req,res)=>{
    const { category, name, description, image, price, rating, stock, veg } = req.body;
    await Product.findByIdAndUpdate(req.params.id, {
        category,
        name,
        description,
        imageUrl: image,
        price,
        rating,
        stock,
        veg
    });
    res.redirect('/admin/products');
})

app.get('/admin/popular', isAdmin, async (req, res) => {
    const products = await Product.find();
    res.render('mostpopular', { products: products });
});

app.put('/admin/popular', isAdmin, async (req, res) => {
    const updatedProduct = await Product.findByIdAndUpdate(
        req.body.productId,
        { ispopular: true },
        { new: true } // To return the updated document
    );
    res.redirect('/admin/popular')
});

app.put('/admin/populars/:id', isAdmin, async (req, res) => {
    const updatedProduct = await Product.findByIdAndUpdate(
        req.params.id,
        { ispopular: false },
        { new: true } // To return the updated document
    );
    res.redirect('/admin/popular')
})

app.get('/admin/seller', isAdmin, async (req, res) => {
    const products = await Product.find();
    res.render('bestseller', { products: products });
});

app.put('/admin/seller', isAdmin, async (req, res) => {
    const updatedProduct = await Product.findByIdAndUpdate(
        req.body.productId,
        { isseller: true },
        { new: true } // To return the updated document
    );
    res.redirect('/admin/seller')
});

app.put('/admin/seller/:id', isAdmin, async (req, res) => {
    const updatedProduct = await Product.findByIdAndUpdate(
        req.params.id,
        { isseller: false },
        { new: true } // To return the updated document
    );
    res.redirect('/admin/seller')
})

app.get('/admin/orders',isAdmin,async (req,res)=>{
    const orders = await Orders.find().populate('user').populate('product.productId');
    res.render('adminorders',{orders:orders})
})

app.get('/login', isAlreadyLoggedIn, (req, res) => {
    res.render("login", { error: "" });
});

app.post('/login', async (req, res) => {
    const check = await User.findOne({ email: req.body.username });
    if (check == null) {
        return res.render("login", { error: "Email address doesn't exist" });
    }
    if (check != null && check.password == req.body.password) {
        const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

        // Delete any existing session logs for the user
        const data = SessionLog.findOne({ userId: check._id });
        console.log(data[0]);
        if(data != null){
            await SessionLog.deleteMany({userId:check._id})
        }

        // Create a new session log

        req.session.isLoggedIn = true;
        req.session.user = check; // Store the user in the session
        req.session.isAdmins = check.role !== 1;
        if (check.role == 1) {
            const sessionLog = new SessionLog({
                userId: check._id,
                ipAddress: ipAddress
            });
            await sessionLog.save();
            res.redirect('/');
        } else {
            res.redirect('/admin');
        }
    } else {
        res.render("login", { error: "Invalid password" });
    }
});

app.get('/register', isAlreadyLoggedIn, (req, res) => {
    res.render("register", { error: "" });
});

app.post('/register', async (req, res) => {
    try {
        const { name, username, password, cpassword } = req.body;
        const check = await User.findOne({ email: username });
        if (check) {
            return res.render("register", { error: "Email already exists" });
        }
        if (password !== cpassword) {
            return res.render("register", { error: "Passwords don't match" });
        }
        const newUser = new User({
            name,
            email: username,
            password,
            role: 1,
            cart: []
        });
        await newUser.save();
        const ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

        // Create a new session log
        const sessionLog = new SessionLog({
            userId: newUser._id,
            ipAddress: ipAddress
        });
        await sessionLog.save();

        req.session.isLoggedIn = true;
        req.session.isAdmin = false;
        req.session.user = newUser; // Store the new user in the session
        res.redirect("/");
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});

app.get('/logout', isAuth, async (req, res) => {
    const sessionLog = await SessionLog.findOne({ userId: req.session.user._id }).sort({ loginTime: -1 });
    if (sessionLog) {
        sessionLog.logoutTime = Date.now();
        await sessionLog.save();
    }
    req.session.destroy();
    res.redirect('/login');
});

// Start the server on port 8000
app.listen(8000, () => {
    console.log('Server is running on port http://localhost:8000');
});
